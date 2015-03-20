#include "pthread.h"
struct pcm_node_t
{
	char pcm[4096];
	struct pcm_node_t * next;
};

struct fifo_t
{
	struct pcm_node_t * head;
	struct pcm_node_t * tail;
	struct pcm_node_t * nodes;
	pthread_mutex_t		lock;
};



int init_fifo(struct fifo_t ** ppfifo , int fifo_size);
int init_empty_fifo(struct fifo_t ** ppfifo);
int in_fifo(struct fifo_t * pfifo , struct pcm_node_t * pnode);
struct pcm_node_t * out_fifo(struct fifo_t * pfifo);
