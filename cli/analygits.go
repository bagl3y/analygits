package main

import (
	"encoding/csv"
	"fmt"
	"os"

	gitlab "github.com/xanzy/go-gitlab"
)

func main() {
	gitURL := os.Getenv("GITLAB_URL")
	accessToken := os.Getenv("GITLAB_TOKEN")

	print("AnalyGitS\n\n")
	git, err := gitlab.NewClient(accessToken, gitlab.WithBaseURL(gitURL))
	if err != nil {
		fmt.Printf("Failed to create GitLab client: %s", err)
		return
	}

	projectopt := &gitlab.ListProjectsOptions{ListOptions: gitlab.ListOptions{PerPage: 100}}
	var allProjects []*gitlab.Project

	for {
		projects, resp, err := git.Projects.ListProjects(projectopt)
		if err != nil {
			fmt.Printf("Failed to list projects: %s", err)
			return
		}

		allProjects = append(allProjects, projects...)

		if resp.NextPage == 0 {
			break
		}

		projectopt.Page = resp.NextPage
	}
	fmt.Printf("Found %d projects\n", len(allProjects))
	// fmt.Print("Projects list:\n")
	// for _, project := range allProjects {
	// 	fmt.Printf(" - %s\n", project.Name)
	// }
	useropt := &gitlab.ListUsersOptions{ListOptions: gitlab.ListOptions{PerPage: 100}, Active: gitlab.Bool(true)}
	users, _, err := git.Users.ListUsers(useropt)
	if err != nil {
		fmt.Printf("Failed to list users: %s", err)
		return
	}

	totalUsers := len(users)
	results := make([][]string, totalUsers+1)         // +1 for header row
	results[0] = []string{"Username", "TotalCommits"} // header row

	for i, user := range users {
		fmt.Printf("Processing user %s - %d/%d\n", user.Username, i+1, totalUsers)

		var totalCommits int

		for j, project := range allProjects {
			// defaultBranch, _, err := git.Branches.GetBranch(project.ID, project.DefaultBranch)
			// if err != nil {
			// 	fmt.Printf("Failed to get default branch for %s: %s\n", project.Name, err)
			// 	continue
			// }
			fmt.Printf("\033[2K\rProcessing project %s - %d/%d", project.Name, j+1, len(allProjects))
			branches, _, err := git.Branches.ListBranches(project.ID, &gitlab.ListBranchesOptions{})
			if err != nil {
				fmt.Printf("Failed to list branches for %s: %s\n", project.Name, err)
				continue
			}

			for _, branch := range branches {
				commits, _, err := git.Commits.ListCommits(project.ID, &gitlab.ListCommitsOptions{
					RefName: &branch.Name,
					All:     gitlab.Bool(true),
				})
				if err != nil {
					fmt.Printf("Failed to list commits for %s/%s: %s\n", project.Name, branch.Name, err)
					continue
				}

				for _, commit := range commits {
					if commit.AuthorName == user.Name || commit.AuthorName == user.Username {
						totalCommits++
					}
				}
			}
		}
		fmt.Printf("Total number of commits for %s: %d\n", user.Username, totalCommits)
		results[i+1] = []string{user.Username, fmt.Sprintf("%d", totalCommits)}
	}

	fmt.Println("Finished processing all users.")
	// Write results to CSV file
	file, err := os.Create("results.csv")
	if err != nil {
		fmt.Printf("Failed to create results file: %s", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, row := range results {
		err := writer.Write(row)
		if err != nil {
			fmt.Printf("Failed to write row to results file: %s", err)
			return
		}
	}
}
