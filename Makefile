all: main	

main : main.o
	gcc -o main main.c -lpcap
clean:
	rm -rf main
	rm -rf *.o
