#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 4096
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5001
#define AES_BLOCK_SIZE 16
#define SECRET_KEY "OP0GVA1ABbK04hC46NkEYsBAykjUNe0dvf+COdW/YGI="

char userID[30] = "";
char password[20] = "";
char regis_id[30] = "";
char regis_password[20] = "";
char *roomName[128] = {};
char *roomPass[128] = {};
bool exit_flag = false;
bool no_room = false;
int sockfd;
struct sockaddr_in auth_addr;
struct sockaddr_in chat_addr;
struct sockaddr_in room_addr;
char jwt[200];
char name_tmp[20];
char pass_tmp[20];
int room_cnt = 0;


void ssl_send(unsigned char *plaintext, int sockfd)
{
    int plaintext_len = strlen((char*)plaintext), ciphertext_len = 0;
    unsigned char buffer[BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 2]; // ciphertext + padding + iv + length
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
	unsigned char length_byte[2];
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SECRET_KEY, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    length_byte[0] = (ciphertext_len >> 8) & 0xff;
    length_byte[1] = ciphertext_len & 0xff;

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, ciphertext, ciphertext_len);
    memcpy(buffer + BUFFER_SIZE + AES_BLOCK_SIZE, iv, AES_BLOCK_SIZE);
	memcpy(buffer + BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE, length_byte, 2);

    send(sockfd, buffer, sizeof(buffer), NULL);
}

void ssl_recv(unsigned char *plaintext, int sockfd)
{
    unsigned char iv[AES_BLOCK_SIZE];
	unsigned char plaintext_buffer[BUFFER_SIZE];
    unsigned char buffer[BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 2]; // ciphertext + padding + iv + length
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];
	unsigned char length_byte[2];

    int ciphertext_len = 0, plaintext_len = 0;
    int recv_len = recv(sockfd, buffer, sizeof(buffer), 0);

    if(recv_len < 0){
        plaintext = NULL;
        return;
    }

    ciphertext_len = (buffer[BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE] << 8) + buffer[BUFFER_SIZE + AES_BLOCK_SIZE + AES_BLOCK_SIZE + 1];

    memcpy(iv, buffer + BUFFER_SIZE + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    memcpy(ciphertext, buffer, BUFFER_SIZE + AES_BLOCK_SIZE);

    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, SECRET_KEY, iv);

    EVP_DecryptUpdate(ctx, plaintext_buffer, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext_buffer + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext_buffer[plaintext_len] = '\0';

	memset(plaintext, 0, sizeof(plaintext));
    memcpy(plaintext, plaintext_buffer, plaintext_len);
    plaintext[plaintext_len] = '\0';
}

void init_scr(){
    initscr();
    start_color();
    init_pair(1, COLOR_WHITE, COLOR_BLACK);
    init_pair(2, COLOR_BLACK, COLOR_WHITE);
    curs_set(1);
    noecho();
    keypad(stdscr, TRUE);

    int windowHeight = 30;
    int windowWidth = 80;
    if(LINES < windowHeight || COLS < windowWidth){
	    endwin();
	    printf("Screen is too small. Minimum size required: %d x %d\n", windowHeight, windowWidth);
	    exit(1);
    }

    WINDOW *mainwin = newwin(windowHeight, windowWidth, 0, 0);

    if(mainwin == NULL){
    	endwin();
		printf("Error creting the main window.\n");
		exit(1);
    }
    scrollok(mainwin, TRUE);
    refresh();

}

void regis(){
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];
	mvprintw(27, 70, "Press F1 to quit");
	mvprintw(28, 70, "                    ");
	mvprintw(28,70, "Press F2 to login");
	refresh();
    memset(regis_id, 0, 30);
    memset(regis_password, 0, 20);
	bool retry = false;
    int key;
    int userIDCursorPosition = 12;
    int userPWCursorPosition = 12;   
    char IDPW_regis[52];

    WINDOW *regis_window = newwin(10, 45, 13, 23);
    wbkgd(regis_window, COLOR_PAIR(2));
    wrefresh(regis_window);
    mvwprintw(regis_window, 3, 2, "user ID :\n");
    mvwprintw(regis_window, 6, 2, "password :\n");
    mvwprintw(regis_window, 1, 18, "register");
    wrefresh(regis_window);
    refresh();

    while(1){
		retry = false;
        key = getch();

		if(key == KEY_F(1)){
			exit_flag = true;
			break;
		}
		if(key ==  KEY_F(2)){
			memset(regis_id, 0, sizeof(regis_id));
			memset(regis_password, 0, sizeof(regis_password));
			return;
		}
		if(key == '\n'){
			if(userIDCursorPosition <= 12){
				userIDCursorPosition = 12;
				memset(regis_id, 0, sizeof(regis_id));
				WINDOW *warn_window = newwin(10, 35, 13, 28);
				wbkgd(warn_window, COLOR_PAIR(2));
				wrefresh(warn_window);
				mvwprintw(warn_window, 3, 10, "Empty user id!");
				mvwprintw(warn_window, 5, 7, "Press Enter to retry");
				wrefresh(warn_window);
				while(1){
					key = getch();

					if(key == '\n'){
						wclear(warn_window);
						delwin(warn_window);
						touchwin(regis_window);
						wrefresh(regis_window);
						break;
					}				 
				}
				continue;
			}
			while(1){
				key = getch();

					if(key == KEY_F(1)){
					exit_flag = true;
					break;
				}
				if(key == '\n'){
					if(userPWCursorPosition <= 12){
						userPWCursorPosition = 12;
						memset(regis_password, 0, sizeof(regis_password));
						WINDOW *warn_window = newwin(10, 35, 13, 28);
						wbkgd(warn_window, COLOR_PAIR(2));
						mvwprintw(warn_window, 3, 10, "Empty password!");
						mvwprintw(warn_window, 5, 7, "Press Enter to retry");
						wrefresh(warn_window);

						while(1){
							key = getch();

						if(key == '\n'){
							wclear(warn_window);
							delwin(warn_window);
							touchwin(regis_window);
							wrefresh(regis_window);
							break;
							}
						}
						continue;
					}
					sockfd = socket(AF_INET, SOCK_STREAM, 0);
					if(sockfd < 0){
						perror("Error: Socket creation failed");
						exit(EXIT_FAILURE);
					}

					memset(&auth_addr, 0, sizeof(auth_addr));
					auth_addr.sin_family = AF_INET;
					auth_addr.sin_port = htons(SERVER_PORT);
					auth_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

					if(connect(sockfd, (struct sockaddr*)&auth_addr, sizeof(auth_addr)) < 0){
						perror("Error: Connection failed");
						close(sockfd);
						exit(EXIT_FAILURE);
					}
					snprintf(IDPW_regis, sizeof(IDPW_regis), "1.%s.%s", regis_id, regis_password);	
					ssl_send(IDPW_regis, sockfd);

					char return_val[20];
					memset(return_val, 0, sizeof(return_val));
					ssl_recv(return_val, sockfd);
					
					if(strcmp(return_val , "ERROR_QUIT") == 0){
						WINDOW *err = newwin(10, 35, 13, 28);
						wbkgd(err, COLOR_PAIR(2));
						wrefresh(err);
						mvwprintw(err, 3, 8, "User ID already existed");
						mvwprintw(err, 5, 7, "Press Enter to retry");
						wrefresh(err);

						while(1){
							key = getch();

							if(key == '\n'){
								retry = true;
								memset(regis_id, 0, 30);
								memset(regis_password, 0, 20);
								wclear(err);
								delwin(err);
								wclear(regis_window);
								mvwprintw(regis_window, 3, 2, "user ID :\n");
    							mvwprintw(regis_window, 6, 2, "password :\n");
    							mvwprintw(regis_window, 1, 13, "register");
								touchwin(regis_window);
								wrefresh(regis_window);
								userIDCursorPosition = 12;
								userPWCursorPosition = 12;
								memset(return_val, 0, sizeof(return_val));
								break;
							}
						}
					}
					close(sockfd);
					break;
				}
				if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
					if(userPWCursorPosition > 12){
						userPWCursorPosition--;
						mvwprintw(regis_window, 6, userPWCursorPosition, " ");
						wrefresh(regis_window);
						regis_password[userPWCursorPosition - 12] = '\0';
					}
				}
				if(key >= 32 && key <= 126){
					if(userPWCursorPosition < 32){
						mvwaddch(regis_window, 6, userPWCursorPosition, key);
						wrefresh(regis_window);
						regis_password[userPWCursorPosition - 12] = key;
						userPWCursorPosition++;
					}
				}
			}
			if(retry)
				continue;
			else
				break;
		}		
		if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
			if(userIDCursorPosition > 12){
				userIDCursorPosition--;
				mvwprintw(regis_window, 3, userIDCursorPosition, " ");
				regis_id[userIDCursorPosition - 12] = '\0';
				wrefresh(regis_window);
			}
		}
		if(key >= 32 && key <= 126){
			if(userIDCursorPosition < 42){
				mvwaddch(regis_window, 3, userIDCursorPosition, key);
				wrefresh(regis_window);
				regis_id[userIDCursorPosition - 12] = key;
				userIDCursorPosition++;
			}
		}
    }

    if(exit_flag)
	    return;

	wclear(regis_window);
	mvwprintw(regis_window, 3, 10, "registered!");
	mvwprintw(regis_window, 4, 8, "Press Enter to login");
	wrefresh(regis_window);

	while(1){
		key = getch();

		if(key == KEY_F(1)){
			exit_flag = true;
			break;
		}
		if(key == '\n'){
			delwin(regis_window);		
			break;
		}
    }
    if(exit_flag)
	    return;
}

void login(){    
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];
	mvprintw(27, 70, "Press F1 to quit");
	mvprintw(28,70, "Press F2 to register");
	refresh();
    memset(userID, 0, 30);
    memset(password, 0, 20);
    bool flag = false;
    int key;
    int userIDCursorPosition = 12;
    int userPWCursorPosition = 12;
    char IDPW[52];
    memset(jwt, 0, 200);

    WINDOW *login_window = newwin(10, 45, 13, 23);
    wbkgd(login_window, COLOR_PAIR(2));
    wrefresh(login_window);

    mvwprintw(login_window, 3, 2, "user ID :\n");
    mvwprintw(login_window, 6, 2, "password :\n");
    wrefresh(login_window);

    while(1){
		flag = false;
        key = getch();

        if(key == KEY_F(1)){
            exit_flag = true;
	    	break;
        }
		if(key == KEY_F(2)){
			regis();
			if(exit_flag){
				return;
			}
			mvprintw(27, 70, "Press F1 to quit");
			mvprintw(28,70, "Press F2 to register");
			refresh();
			memset(userID, 0, 30);
			memset(password, 0 ,20);
			userIDCursorPosition = 12;
			userPWCursorPosition = 12;
			wclear(login_window);
			mvwprintw(login_window, 3, 2, "user ID :\n");
			mvwprintw(login_window, 6, 2, "password :\n");
			wrefresh(login_window);
			continue;
		}
		if(key == '\n'){
			if(userIDCursorPosition <= 12){
				userIDCursorPosition = 12;
				memset(userID, 0, sizeof(userID));

				WINDOW *warn_window = newwin(10, 35, 13, 28);
				wbkgd(warn_window, COLOR_PAIR(2));
				wrefresh(warn_window);
				mvwprintw(warn_window, 3, 10, "Empty user ID!");
				mvwprintw(warn_window, 5, 7, "Press Enter to retry");
				wrefresh(warn_window);

				while(1){
					key = getch();

				if(key == '\n'){
					wclear(warn_window);
					delwin(warn_window);
					touchwin(login_window);
					wrefresh(login_window);
					break;
				}
				}
				continue;
			}
			while(1){
				key = getch();

				if(key == KEY_F(1)){
					exit_flag = true;
					break;
				}
				if(key == KEY_F(2)){
					regis();
					memset(userID, 0, 20);
					memset(password, 0, 20);
					userIDCursorPosition = 12;
					userPWCursorPosition = 12;
					wclear(login_window);
					mvwprintw(login_window, 3, 2, "user ID :\n");
					mvwprintw(login_window, 6, 2, "password :\n");
					wrefresh(login_window);
					flag = true;
					break;
				}
				if(key == '\n'){
					if(userPWCursorPosition <= 12){
						userPWCursorPosition = 12;
						memset(password, 0, sizeof(password));
						WINDOW *warn_window = newwin(10, 35, 13, 28);
						wbkgd(warn_window, COLOR_PAIR(2));
						wrefresh(warn_window);
						mvwprintw(warn_window, 3, 10, "Empty password!");
						mvwprintw(warn_window, 5, 7, "Press Enter to retry");
						wrefresh(warn_window);

						while(1){
							key = getch();

						if(key == '\n'){
							wclear(warn_window);
							delwin(warn_window);
							touchwin(login_window);
							wrefresh(login_window);
							break;
						}
						}
						continue;
					}
					sockfd = socket(AF_INET, SOCK_STREAM, 0);
					if(sockfd < 0){
						perror("Error: Socket creation failed");
						exit(EXIT_FAILURE);
					}
					memset(&auth_addr, 0, sizeof(auth_addr));
					auth_addr.sin_family = AF_INET;
					auth_addr.sin_port = htons(SERVER_PORT);
					auth_addr.sin_addr.s_addr = inet_addr(SERVER_IP);		
					if(connect(sockfd, (struct sockaddr *)&auth_addr, sizeof(auth_addr)) <0){
						perror("Error: Connection failed");
						close(sockfd);
						endwin();
						return;
					}								
					snprintf(IDPW, sizeof(IDPW), "2.%s.%s", userID, password);
					ssl_send(IDPW, sockfd);

					ssl_recv(jwt, sockfd);
					close(sockfd);
					break;
				}				
				if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
					if(userPWCursorPosition > 12){
						userPWCursorPosition--;
						mvwprintw(login_window, 6, userPWCursorPosition, " ");
						wrefresh(login_window);
						password[userPWCursorPosition - 12] = '\0';
					}
				}
				if(key >= 32 && key <= 126){
					if(userPWCursorPosition < 32){
						mvwaddch(login_window, 6, userPWCursorPosition, '*');
						wrefresh(login_window);
						password[userPWCursorPosition - 12] = key;
						userPWCursorPosition++;
					}
				}

			}
			if(exit_flag)
				break;
			if(flag){
				continue;
			}
			else{
				break;
			}
		}
		if(exit_flag)
			break;
		if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
			if(userIDCursorPosition > 12){
				userIDCursorPosition--;
				mvwprintw(login_window, 3, userIDCursorPosition, " ");
				wrefresh(login_window);
				userID[userIDCursorPosition - 12] = '\0';
			}
		}
		if(key >= 32 && key <= 126){
			if(userIDCursorPosition < 42){
				mvwaddch(login_window, 3, userIDCursorPosition, key);
				wrefresh(login_window);
				userID[userIDCursorPosition - 12] = key;
				userIDCursorPosition++;
			}
		}
    }
}

void menu_window(){

    attron(A_BOLD);
    mvprintw(2, 2, "1. chat list");
    mvprintw(4, 2, "2. new chat");
    mvprintw(6, 2, "3. user info");
    mvprintw(8, 2, "4. logout");
    mvprintw(10, 2, "5. exit");
    attroff(A_BOLD);
    refresh();
}

void new_chat(){
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];
	bool retry = false;
    int key;
    int nameCursor = 12;
    int passCursor = 16;
    WINDOW *new_room = newwin(10, 35, 13, 28);
    wbkgd(new_room, COLOR_PAIR(2));
    wrefresh(new_room);
    mvwprintw(new_room, 2, 2, "Room name: ");
    mvwprintw(new_room, 4, 2, "Room password: ");
    wrefresh(new_room);
    while(1){
		retry = false;
        key = getch();

		if(key == KEY_F(1)){
			wclear(new_room);
			touchwin(stdscr);
			return;	    
		}
		if(key == '\n'){
			if(nameCursor <= 12){
	        	nameCursor = 12;
				memset(name_tmp, 0, sizeof(name_tmp));
				WINDOW *warn_window = newwin(10, 35, 13, 28);
				wbkgd(warn_window, COLOR_PAIR(2));
				wrefresh(warn_window);
				mvwprintw(warn_window, 3, 10, "Empty room name!");
				mvwprintw(warn_window, 5, 7, "Press Enter to retry");
				wrefresh(warn_window);
				while(1){
					key = getch();

					if(key == '\n'){
						wclear(warn_window);
						delwin(warn_window);
						touchwin(new_room);
						wrefresh(new_room);
						break;
					}
				}
				continue;
	    	}		
			while(1){
				key = getch();

				if(key == KEY_F(1)){
					wclear(new_room);
					touchwin(stdscr);
					break;
				}
				if(key == '\n'){
					if(passCursor <= 16){
						passCursor = 16;
						memset(pass_tmp, 0, sizeof(pass_tmp));
						WINDOW* warn_window = newwin(10, 35, 13, 28);
						wbkgd(warn_window, COLOR_PAIR(2));
						wrefresh(warn_window);
						mvwprintw(warn_window, 3, 10, "Empty password!");
						mvwprintw(warn_window, 5, 7, "Press Enter to retry");
						wrefresh(warn_window);

						while(1){
							key = getch();

							if(key == '\n'){
								wclear(warn_window);
								delwin(warn_window);
								touchwin(new_room);
								wrefresh(new_room);
								break;
							}				
						}
						continue;
					}
					memset(send_buffer, 0, sizeof(send_buffer));
					snprintf(send_buffer, sizeof(send_buffer), "make:%s:%s", name_tmp, pass_tmp);
					ssl_send(send_buffer, sockfd);
					memset(send_buffer, 0, sizeof(send_buffer));

					memset(recv_buffer, 0, sizeof(send_buffer));
					ssl_recv(recv_buffer, sockfd);

					if(strcmp(recv_buffer, "SUCCESS") != 0){

						WINDOW *err = newwin(10, 35, 13, 28);
						wbkgd(err, COLOR_PAIR(2));
						wrefresh(err);
						mvwprintw(err, 3, 8, "Room already existed");
						mvwprintw(err, 5, 7, "Press Enter to retry");
						wrefresh(err);

						while(1){
							key = getch();

							if(key == '\n'){
								retry = true;
								memset(name_tmp, 0, 30);
								memset(pass_tmp, 0, 20);
								wclear(err);
								delwin(err);
								wclear(new_room);
								mvwprintw(new_room, 2, 2, "Room name: ");
   								mvwprintw(new_room, 4, 2, "Room password: ");
								touchwin(new_room);
								wrefresh(new_room);
								nameCursor = 12;
								passCursor = 16;
								memset(recv_buffer, 0, sizeof(recv_buffer));
								break;
							}
						}
					}
					break;
				}
				if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
					if(passCursor > 16){
						passCursor--;
						mvwprintw(new_room, 4, passCursor, " ");
						wrefresh(new_room);
						pass_tmp[passCursor - 16] = '\0';
					}
				}
				if(key >= 32 && key <= 126){
					if(passCursor < 36){
						mvwaddch(new_room, 4, passCursor, key);
						wrefresh(new_room);
						pass_tmp[passCursor - 16] = key;
						passCursor++;
					}
				}
			}    
			if(retry)
				continue;
			else{
				refresh();
				memset(name_tmp, 0, sizeof(name_tmp));
				memset(pass_tmp, 0, sizeof(pass_tmp));
				wclear(new_room);
				touchwin(stdscr);
				break;
			}
		}
		if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
		    if(nameCursor > 12){
	        	nameCursor--;
				mvwprintw(new_room, 2, nameCursor, " ");
				wrefresh(new_room);
				name_tmp[nameCursor - 12] = '\0';			
	    	}
		}
		if(key >= 32 && key <= 126){
			if(nameCursor < 32){
				mvwaddch(new_room, 2, nameCursor, key);
				wrefresh(new_room);
				name_tmp[nameCursor - 12] = key;
				nameCursor++;
			}
		}
	}
}

void chat_list(WINDOW *list){
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];
	int key;
	ssl_send("list", sockfd);
    wclear(list);
    wrefresh(list);
	scrollok(list, TRUE);
    clear();
    mvprintw(28, 70, "Press F1 to quit");
    mvprintw(30, 0, ">");
    refresh();
    memset(recv_buffer, 0, sizeof(recv_buffer));

	ssl_recv(recv_buffer, sockfd);

	if(strcmp(recv_buffer, "ERROR_QUIT") == 0){
		WINDOW *err = newwin(10, 35, 13, 28);
		wbkgd(err, COLOR_PAIR(2));
		wrefresh(err);
		mvwprintw(err, 3, 10, "Server Error");
		mvwprintw(err, 5, 4, "Press Enter to exit the program");
		wrefresh(err);

		while(1){
			key = getch();

			if(key == '\n'){
				exit_flag = true;
				return;
			}
		}
	}
	if(strcmp(recv_buffer, "EMPTY") == 0){
		WINDOW *err = newwin(10, 35, 13, 28);
		wbkgd(err, COLOR_PAIR(2));
		wrefresh(err);
		mvwprintw(err, 3, 10, "There's no room");
		mvwprintw(err, 5, 7, "Press Enter to return");
		wrefresh(err);

		while(1){

			key = getch();

			if(key == '\n'){
				wclear(err);
				wrefresh(err);
				delwin(err);
				clear();
				touchwin(stdscr);
				refresh();
				no_room = true;
				break;
			}
		}
		return;
	}

    refresh();
    char *token;
    token = strtok(recv_buffer, ".");
	room_cnt = 0;
    while(token != NULL){
    	roomName[room_cnt]=strdup(token);
		token = strtok(NULL, ".");		
		room_cnt++;
    }
    wattron(list, A_BOLD);
    for(int i=0;i<room_cnt;i++){
		wprintw(list, "%d. ", i+1);
    	wprintw(list, roomName[i]);
		wprintw(list, "\n");
    }
    memset(recv_buffer, 0, sizeof(recv_buffer));
    wattroff(list, A_BOLD);
    wrefresh(list);
}

void show_bar(WINDOW *bar){
    wclear(bar);
    mvwprintw(bar, 0, 0, ">");
    wrefresh(bar);
}

void chat(int room_num){
	char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];
	char message[1000];
    WINDOW *chat_bar = newwin(1, 60, 30, 0);    
    wrefresh(chat_bar);
	WINDOW *msg = newwin(28, 80, 0, 0);
	wbkgd(msg, COLOR_PAIR(1));
	wrefresh(msg);
	scrollok(msg, TRUE);
	wattron(msg, A_BOLD);
	wprintw(msg, "Room: %s\n\n", roomName[room_num-1]);
	wattroff(msg, A_BOLD);
	wrefresh(msg);
    show_bar(chat_bar);
	memset(message, 0, sizeof(message));
	
	fd_set read_fds;
	int maxfd;
	struct timeval timeout;
	
    int key;
    int inputCursor = 1;
    while(1){
		FD_ZERO(&read_fds);
		FD_SET(STDIN_FILENO, &read_fds);
		FD_SET(sockfd, &read_fds);

		maxfd = sockfd > STDIN_FILENO ? sockfd : STDIN_FILENO;

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		int ready = select(maxfd + 1, &read_fds, NULL, NULL, &timeout);

		if(ready < 0){
			perror("select");
			break;
		}

		if(FD_ISSET(STDIN_FILENO, &read_fds)){
			key = getch();

			if(key == KEY_F(1)){
				memset(recv_buffer, 0, sizeof(recv_buffer));
				ssl_send("leave", sockfd);
				wclear(msg);
				wrefresh(msg);
				delwin(msg);
				touchwin(stdscr);
				refresh();
				break;
			}			
			if(key == '\n'){			
				if(inputCursor <= 1){
					inputCursor = 1;
					memset(message, 0, sizeof(message));
					WINDOW *warn_window = newwin(10, 35, 13, 28);
					wbkgd(warn_window, COLOR_PAIR(2));
					wrefresh(warn_window);
					mvwprintw(warn_window, 3, 10, "Empty message!");
					mvwprintw(warn_window, 5, 7, "Press Enter to retry");
					wrefresh(warn_window);
					while(1){
						key = getch();

						if(key == '\n'){
							wclear(warn_window);
							delwin(warn_window);
							touchwin(msg);
							wrefresh(msg);
							break;
						}				 
					}
					continue;
				}	

				memset(send_buffer, 0, sizeof(send_buffer));
				snprintf(send_buffer, sizeof(send_buffer), "send:%s", message);
				ssl_send(send_buffer, sockfd);
				memset(send_buffer, 0, sizeof(send_buffer));
				
				wclear(chat_bar);
				mvwprintw(chat_bar, 0, 0, ">");
				wrefresh(chat_bar);
				inputCursor = 1;
				memset(message, 0, sizeof(message));
			}
			if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
				if(inputCursor > 1){
					inputCursor--;
					mvwprintw(chat_bar, 0, inputCursor, " ");
					wrefresh(chat_bar);
					message[inputCursor - 1] = '\0';
				}
			}
			if(key >= 32 && key <= 126){
				if(inputCursor < 70){
					mvwaddch(chat_bar, 0, inputCursor, key);
					wrefresh(chat_bar);
					message[inputCursor - 1] = key;
					inputCursor++;
				}
			}
		}

		if(FD_ISSET(sockfd, &read_fds)){
			memset(recv_buffer, 0, sizeof(recv_buffer));
			ssl_recv(recv_buffer, sockfd);

			if(recv_buffer == NULL)
				break;

			if(strcmp(recv_buffer, "ERROR_QUIT") == 0){
				WINDOW *err = newwin(10, 35, 13, 28);
				wbkgd(err, COLOR_PAIR(2));
				wrefresh(err);
				mvwprintw(err, 3, 10, "Server Error");
				mvwprintw(err, 5, 4, "Press Enter to exit the program");
				wrefresh(err);

				while(1){
					key = getch();

					if(key == '\n'){
						endwin();
						return;
					}
				}
			}

			wprintw(msg, "%s", recv_buffer);
			wrefresh(msg);
			memset(recv_buffer, 0, sizeof(recv_buffer));
		}       						
    }
}

int main(){
    init_scr();
    int key;
    bkgd(COLOR_PAIR(1));
    char send_buffer[BUFFER_SIZE];
	char recv_buffer[BUFFER_SIZE];
    while(1){
    	move(10,40);
		attron(A_BOLD);
		printw("BytingTigers");
		attroff(A_BOLD);		
		refresh();

		while(1){
			login();
			if(exit_flag){
				endwin();
				return 0;
			}
			if(strcmp(jwt, "ERROR_QUIT"))
				break;
			else{
				WINDOW *login_fail = newwin(10, 35, 13, 28);
				wbkgd(login_fail, COLOR_PAIR(2));
				wrefresh(login_fail);
				mvwprintw(login_fail, 4, 10, "Signin failed!");
				mvwprintw(login_fail, 5, 6, "Press Enter to retry");
				wrefresh(login_fail);
				
				while(1){
					key = getch();

					if(key == '\n')
						break;
				}
			}
		}

		close(sockfd);
		clear();
		menu_window();

		char roomNum[5];
		char roomP[30] = "";
		int roomCursor;
		int rpCursor;

		WINDOW *room_list = newwin(10, 40, 0, 0);

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if(sockfd < 0){
			perror("Error: Socket creation failed");
			exit(EXIT_FAILURE);
		}

		chat_addr.sin_family = AF_INET;
		chat_addr.sin_port = htons(5000);
		chat_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

		if(connect(sockfd, (struct sockaddr*)&chat_addr, sizeof(chat_addr)) < 0){
			perror("Error: Connection failed");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		memset(send_buffer, 0, sizeof(send_buffer));
		snprintf(send_buffer, sizeof(send_buffer), "auth:%s:%s", userID, jwt);

		ssl_send(send_buffer, sockfd);
		memset(send_buffer, 0, sizeof(send_buffer));

		memset(recv_buffer, 0, sizeof(recv_buffer));
		ssl_recv(recv_buffer, sockfd);
		
		if(strcmp(recv_buffer, "SUCCESS") != 0){
			printf("authentication failed");
			endwin();
			return 0;
		}
		while(1){
			key = getch();
			if(exit_flag){
				endwin();
				return 0;
			}
			if(key == KEY_F(1)){
				endwin();
				return 0;
			}
			if(key == 49){
				memset(roomNum, 0, sizeof(roomNum));
				roomCursor = 1;
				chat_list(room_list);
				if(no_room){
					menu_window();
					no_room = false;
					continue;
				}
				while(1){
					key = getch();

					if(key == KEY_F(1)){
						clear();
						wclear(room_list);
						touchwin(stdscr);
						menu_window();
						break;
					}
					if(key == '\n'){
						if(atoi(roomNum) > room_cnt){
							roomCursor = 1;
							memset(roomNum, 0, sizeof(roomNum));
							WINDOW *err_win = newwin(10, 35, 13, 28);
							wbkgd(err_win, COLOR_PAIR(2));
							wrefresh(err_win);
							mvwprintw(err_win, 3, 10, "Wrong room number!");
							mvwprintw(err_win, 5, 7, "Press Enter to retry");
							wrefresh(err_win);

							while(1){
								key = getch();

								if(key == '\n'){
									wclear(err_win);
									wrefresh(err_win);
									delwin(err_win);
									chat_list(room_list);
									break;
								}
							}
							continue;
						}
						rpCursor = 16;
						WINDOW *check_pass = newwin(10, 35, 13, 28);
						wbkgd(check_pass, COLOR_PAIR(2));
						wrefresh(check_pass);
						mvwprintw(check_pass, 2, 2, "room password:");
						wrefresh(check_pass);

						while(1){
							key = getch();

							if(key == KEY_F(1)){
								wclear(check_pass);
								wrefresh(check_pass);
								roomCursor = 1;
								memset(roomNum, 0, sizeof(roomNum));
								delwin(check_pass);
								chat_list(room_list);
								break;
							}
							if(key == '\n'){
								refresh();

								memset(send_buffer, 0, sizeof(send_buffer));
								snprintf(send_buffer, sizeof(send_buffer), "join:%s:%s", roomName[atoi(roomNum) - 1], roomP);
								ssl_send(send_buffer, sockfd);
								memset(send_buffer, 0, sizeof(send_buffer));
								
								memset(recv_buffer, 0, sizeof(recv_buffer));
								ssl_recv(recv_buffer, sockfd);
								if(strcmp(recv_buffer, "ERROR_QUIT") == 0){
									WINDOW *err = newwin(10, 35, 13, 28);
									wbkgd(err, COLOR_PAIR(2));
									wrefresh(err);
									mvwprintw(err, 3, 10, "Server Error");
									mvwprintw(err, 5, 4, "Press Enter to exit the program");
									wrefresh(err);

									while(1){
										key = getch();

										if(key == '\n'){
											endwin();
											return 0;
										}
									}
								}
								if(strcmp(recv_buffer, "ERROR") != 0){
									wclear(check_pass);
									wrefresh(check_pass);
									delwin(check_pass);
									wclear(room_list);
									wrefresh(room_list);
									rpCursor = 16;
									memset(recv_buffer, 0, sizeof(recv_buffer));
									chat(atoi(roomNum));
									memset(roomNum, 0, sizeof(roomNum));
									memset(roomP, 0, sizeof(roomP));								
									roomCursor = 1;
									chat_list(room_list);
									break;
								}							
								else{
									WINDOW *error_win = newwin(10, 35, 13, 28);
									wbkgd(error_win, COLOR_PAIR(2));
									wrefresh(error_win);
									mvwprintw(error_win, 3, 10, "Wrong password!");
									mvwprintw(error_win, 5, 7, "Press Enter to retry");
									wrefresh(error_win);

									while(1){
										key = getch();

										if(key == '\n'){
											wclear(error_win);
											delwin(error_win);
											rpCursor = 16;
											memset(roomP, 0, sizeof(roomP));
											wclear(check_pass);
											mvwprintw(check_pass, 2, 2, "room password:");
											wrefresh(check_pass);
											break;
										}
									}
									continue;
								}
							}
							if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
								if(rpCursor > 16){
									rpCursor--;
									mvwprintw(check_pass, 2, rpCursor, " ");
									wrefresh(check_pass);
									roomP[rpCursor - 16] = '\0';
								}
							}
							if(key >= 32 && key <= 126){
								if(rpCursor < 36){
									mvwaddch(check_pass, 2, rpCursor, '*');
									wrefresh(check_pass);
									roomP[rpCursor - 16] = key;
									rpCursor++;
								}
							}
						}
					}
					if(key == KEY_BACKSPACE || key == 127 || key == '\b'){
						if(roomCursor > 1){
							roomCursor--;
							mvprintw(30, roomCursor, " ");
							refresh();
							roomNum[roomCursor - 1] = '\0';
						}
					}
					if(key >= 49 && key <= 57){
						if(roomCursor < 6){
							mvaddch(30, roomCursor, key);
							refresh();
							roomNum[roomCursor - 1] = key;
							roomCursor++;
						}						
					}
				}
			}
			if(key == 50){
				new_chat();
			}		
			if(key == 51){
				WINDOW *info_window = newwin(15, 45, 2, 35);
				wbkgd(info_window, COLOR_PAIR(2));
				mvwprintw(info_window, 2, 2, "user info");
				mvwprintw(info_window, 13, 15, "Press F2 to close this window");
				mvwprintw(info_window, 4, 2, "user ID :");
				mvwprintw(info_window, 4, 12, userID);
				mvwprintw(info_window, 6, 2, "password :");
				mvwprintw(info_window, 6, 12, password);
				wrefresh(info_window);

				while(1){
					key = getch();

					if(key == KEY_F(2)){
						delwin(info_window);
						touchwin(stdscr);
						refresh();
						break;
					}
				}
			}
			if(key == 52){
				memset(userID, 0, sizeof(userID));
				memset(password, 0, sizeof(password));
				clear();
				touchwin(stdscr);
				refresh();
				close(sockfd);
				break;	
			}
			if(key == 53){
				endwin();
				return 0;
			}
		}
    }
}

