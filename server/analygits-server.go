package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	gitlab "github.com/xanzy/go-gitlab"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type UserCommit struct {
	Username            string    `json:"username"`
	Email               string    `json:"email"`
	Name                string    `json:"name"`
	TotalCommits        int       `json:"totalCommits"`
	LastCommitTimestamp time.Time `json:"lastCommitTimestamp"`
}

type UserEmails struct {
	Username string
	Emails   []string
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

func getEmailsForUser(user *gitlab.User, gitURL string, accessToken string) ([]string, error) {
	// Create a new HTTP client
	client := &http.Client{}

	// Create the URL for the request
	url := fmt.Sprintf(gitURL+"/api/v4/users/%d/emails", user.ID)

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add the necessary headers to the request
	req.Header.Add("PRIVATE-TOKEN", accessToken)

	// Send the request
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Parse the response
	var emails []struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(res.Body).Decode(&emails); err != nil {
		return nil, err
	}

	// Extract the email addresses from the response
	emailAddresses := make([]string, len(emails))
	for i, email := range emails {
		emailAddresses[i] = email.Email
	}

	return emailAddresses, nil
}

func main() {
	// Get environment variables
	gitURL := os.Getenv("GITLAB_URL")
	accessToken := os.Getenv("GITLAB_TOKEN")
	mongoURI := os.Getenv("MONGO_URI")
	apiSecretToken := os.Getenv("API_SECRET_TOKEN")
	dbName := os.Getenv("MONGO_DB_NAME")
	collectionName := os.Getenv("MONGO_COLLECTION_NAME")
	logLevelStr := os.Getenv("LOG_LEVEL")
	ddService := os.Getenv("DD_SERVICE")
	ddEnv := os.Getenv("DD_ENV")
	ddVersion := os.Getenv("DD_VERSION")
	// numWorkersStr := os.Getenv("NUM_WORKERS")

	// Parse log level string into logrus.Level
	logLevel, err := logrus.ParseLevel(logLevelStr)
	if err != nil {
		// If parsing fails, set default log level to 'Info'
		logLevel = logrus.InfoLevel
		logrus.Warnf("Invalid log level '%s', defaulting to 'Info'", logLevelStr)
	}

	// Set logger options
	logrus.SetLevel(logLevel)
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrusFields := logrus.Fields{
		"service": ddService,
		"env":     ddEnv,
		"version": ddVersion,
	}

	// Set up GitLab client
	git, err := gitlab.NewClient(accessToken, gitlab.WithBaseURL(gitURL))
	if err != nil {
		logrus.WithFields(logrusFields).Fatalf("Failed to create GitLab client: %s", err)
	}

	// Set up MongoDB client
	if dbName == "" {
		logrus.WithFields(logrusFields).Fatal("MONGO_DB_NAME environment variable not set")
	}

	if collectionName == "" {
		logrus.WithFields(logrusFields).Fatal("MONGO_COLLECTION_NAME environment variable not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if ctx.Err() != nil {
		logrus.WithFields(logrusFields).Errorf("Context error: %s", ctx.Err())
		// Handle the error, e.g., create a new context or skip the operation
	}
	defer cancel()

	logrus.WithFields(logrusFields).Infof("Connecting to MongoDB")

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(mongoURI).SetMaxPoolSize(200))
	if err != nil {
		logrus.WithFields(logrusFields).Fatalf("Failed to connect to MongoDB: %s", err)
	} else {
		logrus.WithFields(logrusFields).Infof("Connected to MongoDB")
	}
	defer client.Disconnect(ctx)

	// Check if API secret token is set
	if apiSecretToken == "" {
		logrus.WithFields(logrusFields).Fatalf("API_SECRET_TOKEN not set")
	}

	// Set up HTTP server
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check if API secret token is correct
		receivedToken := r.URL.Query().Get("token")
		if receivedToken != apiSecretToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			logrus.WithFields(logrusFields).Errorf("Unauthorized request with token %s", receivedToken)
			return
		}
		// Get users and their commit counts from MongoDB
		var userCommits []UserCommit
		findCtx, findCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		collection := client.Database(dbName).Collection(collectionName)
		cursor, err := collection.Find(findCtx, bson.M{})
		if err != nil {
			logrus.WithFields(logrusFields).Errorf("Failed to find users in MongoDB: %s", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer findCancel()

		for cursor.Next(findCtx) {
			var user UserCommit
			if err := cursor.Decode(&user); err != nil {
				logrus.WithFields(logrusFields).Errorf("Failed to decode user from MongoDB: %s", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			userCommits = append(userCommits, user)
		}
		if err := cursor.Err(); err != nil {
			logrus.WithFields(logrusFields).Errorf("MongoDB cursor error: %s", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		// Convert userCommits to JSON and send response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(userCommits); err != nil {
			logrus.WithFields(logrusFields).Errorf("Failed to encode userCommits to JSON: %s", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	})

	// Start HTTP server
	logrus.WithFields(logrusFields).Infof("Starting HTTP server")

	// Mises à jour incrémentielles toutes les 12h
	go func() {
		collection := client.Database(dbName).Collection(collectionName)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if ctx.Err() != nil {
			logrus.WithFields(logrusFields).Errorf("Context error: %s", ctx.Err())
			// Handle the error, e.g., create a new context or skip the operation
		}
		defer cancel()
		logrus.WithFields(logrusFields).Infof("Background job started")
		for {
			startTime := time.Now()
			logrus.WithFields(logrusFields).Infof("Starting update loop")

			// List all projects
			projectopt := &gitlab.ListProjectsOptions{
				ListOptions: gitlab.ListOptions{PerPage: 100},
				Archived:    gitlab.Bool(false),
			}
			logrus.WithFields(logrusFields).Infof("Listing projects")
			var allProjects []*gitlab.Project
			for {
				projects, resp, err := git.Projects.ListProjects(projectopt)
				if err != nil {
					logrus.WithFields(logrusFields).Errorf("Failed to list projects: %s", err)
					break
				}
				allProjects = append(allProjects, projects...)
				if resp.NextPage == 0 {
					break
				}
				projectopt.Page = resp.NextPage
			}
			logrus.WithFields(logrusFields).Infof("Found %d projects", len(allProjects))

			// List all active users
			logrus.WithFields(logrusFields).Infof("Listing users")
			useropt := &gitlab.ListUsersOptions{ListOptions: gitlab.ListOptions{PerPage: 100}, Active: gitlab.Bool(true), WithoutProjectBots: gitlab.Bool(true)}
			users, _, err := git.Users.ListUsers(useropt)
			if err != nil {
				logrus.WithFields(logrusFields).Errorf("Failed to list users: %s", err)
			}
			totalUsers := len(users)
			logrus.WithFields(logrusFields).Infof("Found %d users", totalUsers)
			// Create a map to store the email-userID relationship
			userEmailsMap := make(map[string]*UserEmails)

			for _, user := range users {
				logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.user.ID": user.ID, "git.user.username": user.Username}).Infof("Processing user %s", user.Username)
				// Retrieve the user's emails
				emails, err := getEmailsForUser(user, gitURL, accessToken)
				if err != nil {
					logrus.WithFields(logrusFields).Errorf("Failed to list emails for user %s: %s", user.Username, err)
					continue
				}
				logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.user.ID": user.ID, "git.user.username": user.Username}).Infof("Found %d emails for user %s", len(emails), user.Username)

				// Create a UserEmails object for the user and add it to the map
				userEmails := &UserEmails{
					Username: user.Username,
					Emails:   emails,
				}
				userEmailsMap[user.Username] = userEmails
			}

			logrus.WithFields(logrusFields).Infof("Found %d active users", totalUsers)

			// Compute user commit counts
			userCommitsMap := make(map[string]*UserCommit)
			for i, project := range allProjects {
				logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.project.ID": project.ID, "git.project.name": project.Name}).Infof("Processing project %s - %d/%d", project.Name, i+1, len(allProjects))

				// Get the project details to retrieve the default branch
				projectInfo, _, err := git.Projects.GetProject(project.ID, nil)
				if err != nil {
					logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.project.ID": project.ID, "git.project.name": project.Name}).Errorf("Failed to get project details: %s", err)
					continue
				}
				// Get the project details to retrieve the default branch
				defaultBranch, _, err := git.Branches.GetBranch(project.ID, projectInfo.DefaultBranch)
				if err != nil {
					logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.project.ID": project.ID, "git.project.name": project.Name}).Errorf("Failed to get default branch: %s", err)
					continue
				}

				logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.project.ID": project.ID, "git.project.name": project.Name}).Debugf("Processing branch %s for project %s", defaultBranch.Name, project.Name)
				listCommitsOptions := &gitlab.ListCommitsOptions{
					RefName:     &defaultBranch.Name,
					All:         gitlab.Bool(true),
					ListOptions: gitlab.ListOptions{PerPage: 100},
				}

				var allCommits []*gitlab.Commit
				for {
					commits, resp, err := git.Commits.ListCommits(project.ID, listCommitsOptions)
					if err != nil {
						logrus.WithFields(logrusFields).WithFields(logrus.Fields{"git.project.ID": project.ID, "git.project.name": project.Name, "git.branch.name": defaultBranch.Name}).Errorf("Failed to list commits: %s", err)
						break
					}
					allCommits = append(allCommits, commits...)
					if resp.NextPage == 0 {
						break
					}
					listCommitsOptions.Page = resp.NextPage
				}

				// Loop over all commits
				for _, commit := range allCommits {
					// Check if the author is an active user
					for username, userEmails := range userEmailsMap {
						if contains(userEmails.Emails, commit.AuthorEmail) {
							// Check if the user exists in the temporary userCommits map
							if userCommit, exists := userCommitsMap[username]; exists {
								// Increment the commit count for the user
								userCommit.TotalCommits++
								// Update the last commit timestamp if the current commit is newer
								if commit.CommittedDate.After(userCommit.LastCommitTimestamp) {
									userCommit.LastCommitTimestamp = *commit.CommittedDate
								}
							}
							break // Break the loop as we've found the user
						}
					}
				}

			}

			// Update MongoDB with the userCommitsMap data
			for _, userCommit := range userCommitsMap {
				filter := bson.M{"username": userCommit.Username}
				update := bson.M{"$set": bson.M{
					"username":            userCommit.Username,
					"name":                userCommit.Name,
					"totalCommits":        userCommit.TotalCommits,
					"lastCommitTimestamp": userCommit.LastCommitTimestamp,
				}}

				updateCtx, updateCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer updateCancel()

				_, err := collection.UpdateOne(updateCtx, filter, update, options.Update().SetUpsert(true))
				if err != nil {
					logrus.WithFields(logrusFields).Errorf("Failed to update user commit data in MongoDB: %s", err)
				}
			}
			logrus.WithFields(logrusFields).Infof("Elapsed time: %s", time.Since(startTime))
		}
		// Sleep for 12 hours before running the loop again
		logrus.WithFields(logrusFields).Infof("Background job terminated. It will be restarted in 12 hour")
		cancel()
		time.Sleep(12 * time.Hour)
	}()

	if err := http.ListenAndServe(":8080", nil); err != nil {
		logrus.WithFields(logrusFields).Fatalf("Failed to start HTTP server: %s", err)
	}
}
