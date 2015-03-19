#include "pthread.h"
struct node_t
{
	char pcm[4096];
	struct node_t * next;
};

struct fifo_t
{
	struct node_t * head;
	struct node_t * tail;
	pthread_mutex_t lock;
};

#define init_fifo(ppfifo , fifo_size) do{\
	static struct node_t nodes[fifo_size];\
	static struct fifo_t fifo;\
	int i;\
	\
	pthread_mutex_init(&fifo.lock , NULL);\
	for(i = 0 ; i < fifo_size - 1 ; i++)\
	{\
		nodes[i].pcm[0]= i+6;\
		nodes[i].next = &nodes[i+1];\
	}\
	nodes[i].pcm[0]= 100;\
	nodes[i].next = NULL;\
	\
	fifo.head = &nodes[0];\
	fifo.tail = &nodes[fifo_size - 1];\
	\
	*ppfifo = &fifo;\
}while(0)