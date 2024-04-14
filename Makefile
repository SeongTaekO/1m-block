LDLIBS += -lnetfilter_queue

all: main

main: main.o quick_sort.o boyer_moore_search.o

main.o: main.c

quick_sort.o: quick_sort.c

boyer_moore_search.o: boyer_moore_search.c

clean:
	rm -f main.o
	rm -f main
	rm -f quick_sort.o 
	rm -f boyer_moore_search.o
