#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <regex.h>
#include <errno.h>
#include <pthread.h>
#include <libgen.h>
#include <termios.h>
#include <ctype.h>

#define MAX_PATH 1024
#define MAX_BUFFER 4096
#define MAX_USERS 10
#define MAX_PATTERN 100
#define PASSWORD_FILE ".fileguardian.passwd"
#define BACKUP_DIR ".fileguardian_backups"
#define LOG_FILE ".fileguardian.log"
#define MAGIC_HEADER "MAGIC123"
#define MAGIC_LEN 8
#define GUEST_SEARCH_LIMIT 5
#define MAX_LOG_LINES 20

// global variables
int is_authenticated = 0;
char current_username[50] = {0};
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t keep_running = 1;
int guest_searches_count = 0;

// functions
void signal_handler(int sig);
void log_activity(const char *activity);
void log_key_and_filename(const char *filename, const char *key, const char *operation);

int check_auth_required(const char *operation);
int authenticate_user(const char *username, const char *password);
int register_user(const char *username, const char *password);
void logout_user();
void input_password(char *password, size_t size);

int xor(const char *input_file, const char *output_file, const char *key, int encrypting);
void encrypt(const char *filename, const char *key);
void decrypt(const char *filename, const char *key);

void show_file_info(const char *filename);
void checksumMD5(const char *filename);
void change_file_permission(const char *filename, int permissions);
void view_logs();

void compress(const char *src, const char *dest);
void backup(const char *filename);
void *backup_thread(void *arg);

void recursive_search(const char *base_dir, const char *pattern, regex_t *regex, int* fileCount, int* continue_search);
void search(const char *directory, const char *pattern);

void print_menu();


// Main
int main() {
	int choice;
	char filename[MAX_PATH];
	char key[100];
	char directory[MAX_PATH];
	char pattern[MAX_PATTERN];
	char username[50];
	char password[50];
	int permissions;
	struct termios old_termios;

	signal(SIGINT, signal_handler);
	log_activity("FileGuardian started");

	printf("Welcome to FileGuardian - Advanced File Management System\n");
	printf("=========================================================\n");

	while (keep_running) {
		print_menu();

		if (scanf("%d", &choice) != 1) {
			printf("Invalid input. Please enter a number.\n");
			while (getchar() != '\n');
			continue;
		}
		while (getchar() != '\n');

		switch (choice) {
			case 1: // Encrypt File
				if(!check_auth_required("File Encryption")) break;
				printf("Enter filename to encrypt: ");
				if (fgets(filename, sizeof(filename), stdin)) {
					filename[strcspn(filename, "\n")] = 0; // Remove newline
					printf("Enter encryption key: ");
					if (fgets(key, sizeof(key), stdin)) {
						key[strcspn(key, "\n")] = 0; // Remove newline
						encrypt(filename, key);
					}
				}
				break;
		
			case 2: // Decrypt File
				if(!check_auth_required("File Decryption")) break;
				printf("Enter filename to decrypt: ");
				if (fgets(filename, sizeof(filename), stdin)) {
					filename[strcspn(filename, "\n")] = 0; // Remove newline
					printf("Enter decryption key: ");
					if (fgets(key, sizeof(key), stdin)) {
						key[strcspn(key, "\n")] = 0; // Remove newline
						decrypt(filename, key);
					}
				}
				break;
		
			case 3: // Search Files
				printf("Enter directory to search (or . for current): ");
				if (fgets(directory, sizeof(directory), stdin)) {
					directory[strcspn(directory, "\n")] = 0; // Remove newline
					printf("Enter search pattern (regex): ");
					if (fgets(pattern, sizeof(pattern), stdin)) {
						pattern[strcspn(pattern, "\n")] = 0; // Remove newline
						search(directory, pattern);
					}
				}
				break;
		
			case 4: // Backup File
				if(!check_auth_required("File Backup")) break;
				printf("Enter filename to backup: ");
				if (fgets(filename, sizeof(filename), stdin)) {
					filename[strcspn(filename, "\n")] = 0; // Remove newline
			
					// Create background thread for backup
					pthread_t backup_tid;
					char *filename_copy = malloc(strlen(filename) + 1);
					if (filename_copy) {
						strcpy(filename_copy, filename);
						if (pthread_create(&backup_tid, NULL, backup_thread, filename_copy) != 0) {
							printf("Failed to create backup thread. Performing backup in foreground.\n");
							backup(filename);
							free(filename_copy);
						} else {
							pthread_detach(backup_tid); // Detach thread
							printf("Backup started in background thread.\n");
						}
					}
				}
				break;
		
			case 5: // Calculate Checksum
				printf("Enter filename for checksum calculation: ");
				if (fgets(filename, sizeof(filename), stdin)) {
					filename[strcspn(filename, "\n")] = 0; // Remove newline
					checksumMD5(filename);
				}
				break;
		
			case 6: // Show File Info
				printf("Enter filename for information: ");
				if (fgets(filename, sizeof(filename), stdin)) {
					filename[strcspn(filename, "\n")] = 0; // Remove newline
					show_file_info(filename);
				}
				break;
		
			case 7: // View Logs
				if(!check_auth_required("Program Logs")) break;
				view_logs();
				break;
		
			case 8: // Change Permissions
				if(!check_auth_required("Permission Change")) break;
				printf("Enter filename to change permissions: ");
				if (fgets(filename, sizeof(filename), stdin)) {
					filename[strcspn(filename, "\n")] = 0; // Remove newline
					printf("Enter new permissions (octal, e.g., 755): ");
					if (scanf("%o", &permissions) == 1) {
						while (getchar() != '\n'); // Clear input buffer
						change_file_permission(filename, permissions);
					} else {
						printf("Invalid permission format.\n");
						while (getchar() != '\n'); // Clear input buffer
					}
				}
				break;
		
			case 9: // Login
				if (is_authenticated) {
					printf("Already logged in as %s\n", current_username);
					break;
				}
		
				printf("Enter username: ");
				if (fgets(username, sizeof(username), stdin)) {
					username[strcspn(username, "\n")] = 0; // Remove newline
			
					// Get terminal settings for password input
					tcgetattr(STDIN_FILENO, &old_termios);
					input_password(password, sizeof(password));
			
					if (authenticate_user(username, password)) {
						is_authenticated = 1;
						strncpy(current_username, username, sizeof(current_username) - 1);
						current_username[sizeof(current_username) - 1] = '\0';
						guest_searches_count = 0; // Reset guest counter
				
						char activity[MAX_BUFFER];
						snprintf(activity, MAX_BUFFER, "User '%s' logged in successfully", username);
						log_activity(activity);
				
						printf("Login successful! Welcome, %s\n", username);
					} else {
						printf("Login failed. Invalid username or password.\n");
						log_activity("Failed login attempt");
					}
			
					// Clear password from memory
					memset(password, 0, sizeof(password));
				}
				break;
		
			case 10: // Register
				printf("Enter new username: ");
				if (fgets(username, sizeof(username), stdin)) {
					username[strcspn(username, "\n")] = 0; // Remove newline
			
					// Get terminal settings for password input
					tcgetattr(STDIN_FILENO, &old_termios);
					input_password(password, sizeof(password));
			
					int result = register_user(username, password);
					if (result == 1) {
						printf("Registration successful! You can now login.\n");
						char activity[MAX_BUFFER];
						snprintf(activity, MAX_BUFFER, "New user registered: %s", username);
						log_activity(activity);
					} else if (result == 0) {
						printf("Registration failed. Username already exists.\n");
					} else {
						printf("Registration failed. Error accessing user database.\n");
					}
			
					// Clear password from memory
					memset(password, 0, sizeof(password));
				}
				break;
		
			case 11: // Logout
				logout_user();
				break;
		
			case 0: // Exit
				printf("Shutting down FileGuardian...\n");
				if (is_authenticated) {
					char activity[MAX_BUFFER];
					snprintf(activity, MAX_BUFFER, "User '%s' logged out (system shutdown)", current_username);
					log_activity(activity);
				}
				log_activity("FileGuardian shutdown");
				keep_running = 0;
				break;
		
			default:
				printf("Invalid choice. Please select a valid option.\n");
				break;
		}

		if (keep_running && choice != 0) {
			printf("\nPress Enter to continue...");
			getchar();
		}
	}

	pthread_mutex_destroy(&log_mutex);
	printf("FileGuardian terminated successfully.\n");

	return 0;
}

// 시그널 핸들러
void signal_handler(int sig) {
	if (sig == SIGINT) {
		printf("\nReceived interrupt signal. Cleaning up and exiting...\n");
		keep_running = 0;
	}
}

// 시간과 사용자 이름, 프로그램 사용 기록을 로그 파일에 업데이트
void log_activity(const char *activity) {
    //여러 스레드가 동시에 로그 파일에 접근하지 않도록 잠금
	pthread_mutex_lock(&log_mutex);

	int log_fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (log_fd >= 0) {
		time_t now = time(NULL);
		char timestamp[100];
		strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

		char log_entry[1024];
		int len = snprintf(log_entry, sizeof(log_entry), "[%s] User: %s - %s\n",
			timestamp,
			is_authenticated ? current_username : "Guest",
			activity);

		write(log_fd, log_entry, len);

		close(log_fd);
	}

	pthread_mutex_unlock(&log_mutex);
}

// 암호화-복호화에 사용된 키를 저장
void log_key_and_filename(const char *filename, const char *key, const char *operation) {
	int log_fd = open("encryption_log.txt", O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (log_fd < 0) {
		perror("Error opening log file");
		return;
	}

	char log_entry[1024];
	int len = snprintf(log_entry, sizeof(log_entry),
		"Operation: %s, Filename: %s, Key: %s\n",
		operation, filename, key);

	write(log_fd, log_entry, len);

	close(log_fd);
}

// Check if authentication is required for operation
int check_auth_required(const char *operation) {
	if (!is_authenticated) {
		printf("Access Denied: '%s' requires user authentication.\n", operation);
		printf("Please login to access this feature.\n");
		log_activity("Unauthorized access attempt");
		return 0;
	}
	return 1;
}

// User authentication (login)
int authenticate_user(const char *username, const char *password) {
  FILE *file = fopen(PASSWORD_FILE, "r");
  char line[100], file_username[50], file_password[50];

  if (file == NULL) {
      // Password file doesn't exist yet
      return 0;
  }

  while (fgets(line, sizeof(line), file)) {
    // Remove newline character
    line[strcspn(line, "\n")] = 0;

    if (sscanf(line, "Username: %49[^,], Password: %49s", file_username, file_password) == 2) {
        if (strcmp(username, file_username) == 0 && strcmp(password, file_password) == 0) {
            fclose(file);
            return 1; // Authentication successful
        }
    }
}

  fclose(file);
  return 0; // Authentication failed
}

// Register new user
int register_user(const char *username, const char *password) {
  FILE *file = fopen(PASSWORD_FILE, "r");
  char line[100], file_username[50], file_password[50];

  if (file == NULL) {
      // Password file doesn't exist, create it in write mode
      file = fopen(PASSWORD_FILE, "w");
      if (file == NULL) {
          return -1; // File creation failed
      }
      fprintf(file, "Username: %s, Password: %s\n", username, password); // Write new user to file
      fclose(file);
      return 1; // Registration successful
  }

  // Check if username already exists
  while (fgets(line, sizeof(line), file)) {
      // Remove newline character
      line[strcspn(line, "\n")] = 0;

      // Parse username and password from line
      if (sscanf(line, "Username: %49[^,], Password: %49s", file_username, file_password) == 2) {
          if (strcmp(username, file_username) == 0) {
              fclose(file);
              return 0; // Username already exists
          }
      }
  }

  // Close the file after reading before reopening in append mode
  fclose(file);

  // Username doesn't exist, register new user
  file = fopen(PASSWORD_FILE, "a"); // Open file in append mode
  if (file == NULL) {
      return -1; // Error opening file for appending
  }
  fprintf(file, "Username: %s, Password: %s\n", username, password); // Write new user to file
  fclose(file);

  return 1; // Registration successful
}

// Logout function
void logout_user() {
    if (is_authenticated) {
        char activity[MAX_BUFFER];
        snprintf(activity, MAX_BUFFER, "User '%s' logged out", current_username);
        log_activity(activity);
        
        is_authenticated = 0;
        memset(current_username, 0, sizeof(current_username));
        guest_searches_count = 0; // Reset guest search counter
        
        printf("Successfully logged out.\n");
    } else {
        printf("No user is currently logged in.\n");
    }
}

// 비밀번호 입력 시 *로 가림
void input_password(char *password, size_t size) {
	struct termios old;
	tcgetattr(STDIN_FILENO, &old);

	struct termios new = old;
	new.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(STDIN_FILENO, TCSANOW, &new);

	int index = 0;
	char ch;

	printf("Enter your password: ");
	fflush(stdout);
	while (read(STDIN_FILENO, &ch, 1) > 0 && ch != '\n') {
		if (ch == 127 || ch == 8) {  // Handle backspace
			if (index > 0) {
				printf("\b \b");
				fflush(stdout);
				index--;
			}
		} else {
			if (index < size - 1) {
				password[index++] = ch;
				printf("*");
				fflush(stdout);
			}
		}
	}
	password[index] = '\0';  // Null terminate the password
	tcsetattr(STDIN_FILENO, TCSANOW, &old);
	printf("\n");
}

int xor(const char *input_file, const char *output_file, const char *key, int encrypting) {
	int in_fd, out_fd;
	char buffer[1024];
	ssize_t bytes_read, bytes_written;
	size_t i, key_len;

	in_fd = open(input_file, O_RDONLY);
	if (in_fd < 0) {
		perror("Error opening input file");
		return -1;
	}

	out_fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd < 0) {
		perror("Error opening output file");
		close(in_fd);
		return -1;
	}

	key_len = strlen(key);

	if (encrypting) {
		// Write encrypted header
		char header[MAGIC_LEN];
		memcpy(header, MAGIC_HEADER, MAGIC_LEN);
		for (i = 0; i < MAGIC_LEN; i++) {
			header[i] ^= key[i % key_len];
		}
		if (write(out_fd, header, MAGIC_LEN) != MAGIC_LEN) {
			perror("Error writing header");
			close(in_fd);
			close(out_fd);
			return -1;
		}
	} else {
		// Read and verify encrypted header
		char header[MAGIC_LEN];
		if (read(in_fd, header, MAGIC_LEN) != MAGIC_LEN) {
			fprintf(stderr, "Error reading header\n");
			close(in_fd);
			close(out_fd);
			return -1;
		}
		for (i = 0; i < MAGIC_LEN; i++) {
			header[i] ^= key[i % key_len];
		}
        if (strncmp(header, MAGIC_HEADER, MAGIC_LEN) != 0) {
            fprintf(stderr, "Incorrect decryption key or corrupted file\n");
            close(in_fd);
            close(out_fd);
            unlink(output_file);
            return -1;
        }
    }

    // Process file contents
    while ((bytes_read = read(in_fd, buffer, sizeof(buffer))) > 0) {
        for (i = 0; i < bytes_read; i++) {
            buffer[i] ^= key[i % key_len];
        }
        bytes_written = write(out_fd, buffer, bytes_read);
        if (bytes_written != bytes_read) {
            perror("Error writing data");
            close(in_fd);
            close(out_fd);
            return -1;
        }
    }

    close(in_fd);
    close(out_fd);
    return 0;
}

void encrypt(const char *filename, const char *key) {
    char temp_file[MAX_PATH];
    char activity[MAX_BUFFER];

    snprintf(temp_file, MAX_PATH, "%s.encrypted", filename);

    if (xor(filename, temp_file, key, 1) == 0) {
        if (rename(temp_file, filename) != 0) {
            perror("Error renaming file");
            unlink(temp_file);
            return;
        }

        snprintf(activity, MAX_BUFFER, "Encrypted file: %s", filename);
        log_activity(activity);
        printf("File '%s' successfully encrypted\n", filename);

        log_key_and_filename(filename, key, "Encrypt");
    }
}

void decrypt(const char *filename, const char *key) {    
    char temp_file[MAX_PATH];
    char activity[MAX_BUFFER];

    snprintf(temp_file, MAX_PATH, "%s.decrypted", filename);

    if (xor(filename, temp_file, key, 0) == 0) {
        if (rename(temp_file, filename) != 0) {
            perror("Error renaming file");
            unlink(temp_file);
            return;
        }

        snprintf(activity, MAX_BUFFER, "Decrypted file: %s", filename);
        log_activity(activity);
        printf("File '%s' successfully decrypted\n", filename);

        log_key_and_filename(filename, key, "Decrypt");
    }
}

// Show detailed file information
void show_file_info(const char *filename) {
	struct stat file_stat;
	struct passwd *pw;
	struct group *gr;
	char activity[MAX_BUFFER];
	char time_str[100];
	
	if (stat(filename, &file_stat) == -1) {
		perror("Error getting file info");
		return;
	}
	
	// Get user and group info
	pw = getpwuid(file_stat.st_uid);
	gr = getgrgid(file_stat.st_gid);
	
	printf("\nFile Information for: %s\n", filename);
	printf("--------------------------------------------------\n");
	printf("Size: %ld bytes\n", file_stat.st_size);
	printf("Permissions: %o\n", file_stat.st_mode & 0777);
	
	// Format file permission string
	char perm[11];
	perm[0] = S_ISDIR(file_stat.st_mode) ? 'd' : '-';
	perm[1] = (file_stat.st_mode & S_IRUSR) ? 'r' : '-';
	perm[2] = (file_stat.st_mode & S_IWUSR) ? 'w' : '-';
	perm[3] = (file_stat.st_mode & S_IXUSR) ? 'x' : '-';
	perm[4] = (file_stat.st_mode & S_IRGRP) ? 'r' : '-';
	perm[5] = (file_stat.st_mode & S_IWGRP) ? 'w' : '-';
	perm[6] = (file_stat.st_mode & S_IXGRP) ? 'x' : '-';
	perm[7] = (file_stat.st_mode & S_IROTH) ? 'r' : '-';
	perm[8] = (file_stat.st_mode & S_IWOTH) ? 'w' : '-';
	perm[9] = (file_stat.st_mode & S_IXOTH) ? 'x' : '-';
	perm[10] = '\0';
	
	printf("Permissions (symbolic): %s\n", perm);
	printf("Owner: %s (%d)\n", pw ? pw->pw_name : "Unknown", file_stat.st_uid);
	printf("Group: %s (%d)\n", gr ? gr->gr_name : "Unknown", file_stat.st_gid);
	
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&file_stat.st_mtime));
	printf("Last modified: %s\n", time_str);
	
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&file_stat.st_atime));
	printf("Last accessed: %s\n", time_str);
	
	strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&file_stat.st_ctime));
	printf("Last status change: %s\n", time_str);
	
	printf("Inode: %lu\n", file_stat.st_ino);
	printf("Number of hard links: %lu\n", file_stat.st_nlink);
	
	snprintf(activity, MAX_BUFFER, "Viewed information for file '%s'", filename);
	log_activity(activity);
}

// Calculate and display MD5 checksum using external md5sum command
void checksumMD5(const char *filename) {
	char command[MAX_PATH + 10];
	char activity[MAX_BUFFER];
	
	// Create command to execute md5sum
	snprintf(command, sizeof(command), "md5sum \"%s\"", filename);
	
	printf("Calculating MD5 checksum for '%s':\n", filename);
	
	// Execute command and capture output
	FILE *fp = popen(command, "r");
	if (fp == NULL) {
		perror("Failed to run md5sum command");
		return;
	}
	
	// Read output
	char output[MAX_BUFFER];
	if (fgets(output, sizeof(output), fp) != NULL) {
		printf("%s", output);
		
		snprintf(activity, MAX_BUFFER, "Calculated checksum for file '%s'", filename);
		log_activity(activity);
	} else {
		printf("Error calculating checksum\n");
	}
	
	pclose(fp);
}


// Change file permission (Auth required)
void change_file_permission(const char *filename, int permissions) {    
    char activity[MAX_BUFFER];
    
    if (chmod(filename, permissions) == 0) {
        printf("Permissions for '%s' changed to %o\n", filename, permissions);
        snprintf(activity, MAX_BUFFER, "Changed permissions for file '%s' to %o", 
                 filename, permissions);
        log_activity(activity);
    } else {
        perror("Error changing file permissions");
    }
}

// View system logs (Auth required)
void view_logs() {
	int fd = open(LOG_FILE, O_RDONLY);
	if (fd == -1) {
		perror("Error opening log file");
		return;
	}
	
	off_t pos = lseek(fd, 0, SEEK_END);
	if(pos == -1){
		perror("lseek failed");
		close(fd);
		return;
	}

	int lineCount = 0;
	char buffer;
	size_t file_size = pos;
	size_t buf_index = 0;
	char *line_buf = malloc(file_size);
	if(!line_buf){
		perror("malloc failed");
		close(fd);
		return;
	}

	//거꾸로 줄 세기
	while(pos > 0 && lineCount <= MAX_LOG_LINES){
		pos--;
		if(lseek(fd, pos, SEEK_SET) == -1) break;
		if(read(fd, &buffer, 1) != 1) break;
		line_buf[buf_index++] = buffer;
		if(buffer == '\n') lineCount++;
	}

	//로그출력
	if(buf_index > 0){
		printf("\n========== System Logs (last %d lines) ==========\n", MAX_LOG_LINES);
		for(ssize_t i = buf_index - 1; i >= 0; i--){
			putchar(line_buf[i]);
		}
	} else{
		printf("log file is empty\n");
	}

	free(line_buf);
	close(fd);

	log_activity("Viewed system logs");
}

// Compress file using external gzip
void compress(const char *src, const char *dest) {
	pid_t pid;
	int status;
	
	pid = fork();
	
	if (pid == -1) {
		perror("Fork failed");
		return;
	} else if (pid == 0) { // Child process
		// Redirect stdout to the destination file
		int fd = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
			perror("Failed to open destination file");
			exit(EXIT_FAILURE);
		}
		
		dup2(fd, STDOUT_FILENO);
		close(fd);
		
		// Execute gzip
		execlp("gzip", "gzip", "-c", src, NULL);
		
		// If execlp returns, it's an error
		perror("Failed to execute gzip");
		exit(EXIT_FAILURE);
	} else { // Parent process
		waitpid(pid, &status, 0);
		
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			printf("\nFile compressed successfully\n");
		} else {
			printf("Compression failed\n");
		}
	}
}

// Backup function (Auth required)
void backup(const char *filename){
	
	char backup_path[MAX_PATH];
	char compressed_file[MAX_PATH];
	struct stat st = {0};
	char activity[MAX_BUFFER];
	time_t now = time(NULL);
	char timestamp[20];
	
	// Create backup directory if it doesn't exist
	if (stat(BACKUP_DIR, &st) == -1) {
		mkdir(BACKUP_DIR, 0700);
	}
	
	// Generate timestamp for the backup file
	strftime(timestamp, sizeof(timestamp), "%Y%m%d%H%M%S", localtime(&now));
	
	// Get the base filename
	char *base = basename(strdup(filename));
	
	// Safely construct backup_path
	if (snprintf(backup_path, MAX_PATH, "%s/%s_%s", BACKUP_DIR, base, timestamp) >= MAX_PATH) {
		fprintf(stderr, "Error: backup_path too long\n");
		return;
	}
	
	// Safely construct compressed_file
	if (snprintf(compressed_file, MAX_PATH, "%s.gz", backup_path) >= MAX_PATH) {
		fprintf(stderr, "Error: compressed_file path too long\n");
		return;
	}
	
	// Compress and backup the file
	compress(filename, compressed_file);
	
	snprintf(activity, MAX_BUFFER, "Created backup of file '%s' to '%s.gz'", filename, backup_path);
	log_activity(activity);
	
	printf("\nBackup created: %s.gz\n", backup_path);
}

// Thread function for background backup
void *backup_thread(void *arg) {
	const char *filename = (const char *)arg;
	char activity[MAX_BUFFER];
	
	printf("\nStarting backup of '%s' in background thread...\n", filename);
	
	// Perform backup operation
	backup(filename);
	
	snprintf(activity, MAX_BUFFER, "Completed background backup of file '%s'", filename);
	log_activity(activity);
	
	free(arg); // Free the allocated memory for filename
	return NULL;
}

// Recursive search with regex
void recursive_search(const char *base_dir, const char *pattern, regex_t *regex, int* fileCount, int* continue_search) {
	if (!(*continue_search)) return;

	DIR *dir;
	struct dirent *entry;
	char path[MAX_PATH];
	struct stat info;

	if ((dir = opendir(base_dir)) == NULL) {
		perror("opendir");
		return;
	}

	while ((entry = readdir(dir)) != NULL && keep_running && continue_search) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(path, MAX_PATH, "%s/%s", base_dir, entry->d_name);

		if (stat(path, &info) != 0) {
			perror("stat");
			continue;
		}

		if (S_ISDIR(info.st_mode)) {
			recursive_search(path, pattern, regex, fileCount, continue_search);
		} else {
			if (regexec(regex, entry->d_name, 0, NULL, 0) == 0) {
				(*fileCount)++;

				printf("Found: %s\n", path);
				printf("  - Size: %ld bytes\n", info.st_size);
				printf("  - Last modified: %s", ctime(&info.st_mtime));

				char activity[MAX_BUFFER];
				snprintf(activity, MAX_BUFFER, "Found file matching pattern '%s': %s", pattern, path);
				log_activity(activity);

				if ((*fileCount) % 10 == 0) {
					printf("\n--- Found %d files so far. Continue searching? (y/n): ", *fileCount);
					char answer[10];
					if (fgets(answer, sizeof(answer), stdin)) {
						if (tolower(answer[0]) == 'n') {
							(*continue_search) = 0;
							printf("Search stopped by user.\n");
							break;
						}
					}
				}
			}
		}
	}
	closedir(dir);
}



// Search files using regex (limited for guests)
void search(const char *directory, const char *pattern) {
	int fileCount = 0;
	int continue_search = 1;

	// Check guest limitations
	if (!is_authenticated) {
		if (guest_searches_count >= GUEST_SEARCH_LIMIT) {
			printf("Access Limited: Guest users can only perform %d searches per session.\n", GUEST_SEARCH_LIMIT);
			printf("Please login to remove this limitation.\n");
			log_activity("Guest search limit exceeded");
			return;
		}
		guest_searches_count++;
		printf("Guest mode: %d/%d searches remaining in this session.\n", GUEST_SEARCH_LIMIT - guest_searches_count, GUEST_SEARCH_LIMIT);
	}
	
	regex_t regex;
	int ret;
	char activity[MAX_BUFFER];
	
	ret = regcomp(&regex, pattern, REG_EXTENDED);
	if (ret != 0) {
		char error_message[MAX_BUFFER];
		regerror(ret, &regex, error_message, MAX_BUFFER);
		fprintf(stderr, "Regex compilation failed: %s\n", error_message);
		return;
	}
	
	printf("Searching for files matching pattern '%s' in directory '%s'...\n", pattern, directory);
	
	snprintf(activity, MAX_BUFFER, "Searching for pattern '%s' in directory '%s'", pattern, directory);
	log_activity(activity);
	

	recursive_search(directory, pattern, &regex, &fileCount, &continue_search);
	
	regfree(&regex);
}

// Complete print_menu() function
void print_menu() {
	printf("==========================================\n");
	printf("\tFileGuardian - File Manager\n");
	printf("==========================================\n");
	
	if (is_authenticated) {
		printf("Logged in as: %s\n\n", current_username);
	} else {
		printf("Not logged in (Guest mode)\n");
		printf("Limited functionality available\n\n");
	}
	
	printf(" 1. Encrypt File (Auth Required)\n");
	printf(" 2. Decrypt File (Auth Required)\n");
	printf(" 3. Search Files\n");
	printf(" 4. Backup File (Auth Required)\n");
	printf(" 5. Calculate File Checksum\n");
	printf(" 6. Show File Information\n");
	printf(" 7. View System Logs (Auth Required)\n");
	printf(" 8. Change File Permissions (Auth Required)\n");
	printf(" 9. Login\n");
	printf("10. Register New User\n");
	printf("11. Logout\n");
	printf(" 0. Exit\n");
	printf("==========================================\n");
	printf("Enter your choice: ");
}
