# FileGuardian

FileGuardian은 암호화, 백업, 파일 권한 수정 등의 기능을 통해 사용자가 파일을 안전하게 관리할 수 있도록 지원하는 프로그램입니다.

<br>

## Project Structure

- `FileGuardian.c` — 전체 기능 구현
- `.fileguardian.passwd` — 사용자 정보 저장
- `.fileguardian.log` — 시스템 로그 파일
- `.fileguardian_backups/` — 백업 파일 저장 디렉토리

<br>

## Getting Started

1. 컴파일
   ```bash
   make
   ```

2. 실행
   ```bash
   ./fileguardian
   ```

<br>


## Functionalities

- XOR 방식 파일 암호화 / 복호화
- 정규표현식 기반 파일 검색
- 다중 스레드 기반 파일 백업 및 압축
- 파일 메타데이터 출력
- MD5 체크섬 확인
- 파일 권한 변경
- 시스템 로그 출력
- 사용자 인증 (로그인/회원가입)

<br>

## Menu display examples

```
==========================================
        FileGuardian - File Manager
==========================================
Not logged in (Guest mode)
Limited functionality available

 1. Encrypt File (Auth Required)
 2. Decrypt File (Auth Required)
 3. Search Files
 4. Backup File (Auth Required)
 5. Calculate File Checksum
 6. Show File Information
 7. View System Logs (Auth Required)
 8. Change File Permissions (Auth Required)
 9. Login
10. Register New User
11. Logout
 0. Exit
==========================================
```
  
<br><br><br>
  
  

**1. Encrypt File (Auth Required)**

```
==========================================
Enter your choice: 1
Enter filename to encrypt:
Enter encryption key:
```
  
<br>

**2. Decrypt File (Auth Required)**

```
==========================================
Enter your choice: 2
Enter filename to decrypt: 
Enter decryption key:
```

<br>


**3. Search Files**  
```
==========================================
Enter your choice: 3
Enter directory to search (or . for current): 
Enter search pattern (regex): 
```

<br>


**4. Backup File (Auth Required)**  
```
==========================================
Enter your choice: 4
Enter filename to backup:
```
 
<br>


**5. Calculate File Checksum**  
```
==========================================
Enter your choice: 5
Enter filename for checksum calculation:
```
  
<br>



**6. Show File Information**  
```
==========================================
Enter your choice: 6
Enter filename for information:
```
  
<br>



**7. View System Logs (Auth Required)**  
```
==========================================
Enter your choice: 7

```
  
<br>



**8. Change File Permissions (Auth Required)**  
```
==========================================
Enter your choice: 8
Enter filename to change permissions:
```
  

<br>


**9. Login**  
```
==========================================
Enter your choice: 9
Enter username:
Enter your password:
```
  

<br>


**10. Register New User**  
```
==========================================
Enter your choice: 10
Enter new username:
Enter your password:
```

<br>


**11. Logout**  
```
==========================================
Enter your choice: 11
Successfully logged out.
```

<br><br>



## Team

Team 20
- Khabibilo
- Kim Mi-sung
- Choi Yun-sung
