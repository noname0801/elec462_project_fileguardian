# Makefile for FileGuardian

# 컴파일러와 옵션
CC = gcc
CFLAGS = -Wall -pthread

# 대상 실행 파일
TARGET = FileGuardian

# 기본 규칙
all: $(TARGET)

# 실행 파일 생성 규칙
$(TARGET): FileGuardian.c
	$(CC) $(CFLAGS) -o $(TARGET) FileGuardian.c

# 실행
run: $(TARGET)
	./$(TARGET)

# 정리
clean:
	rm -f $(TARGET)
