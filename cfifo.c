#include <stdio.h>
#include <stdlib.h>
#include "cfifo.h"

int init_empty_fifo(struct fifo_t ** ppfifo)
{
	static struct fifo_t fifo;
	pthread_mutex_init(&fifo.lock , NULL);

	fifo.head = NULL;
	fifo.tail = NULL;
	fifo.nodes = NULL;
	*ppfifo = &fifo;

	return 0;
}

int init_fifo(struct fifo_t ** ppfifo , int fifo_size) 
{
	static struct fifo_t fifo;
	int i;
	struct pcm_node_t *  nodes = (struct pcm_node_t *)malloc(sizeof(struct pcm_node_t) * fifo_size);
	
	pthread_mutex_init(&fifo.lock , NULL);
	for(i = 0 ; i < fifo_size - 1 ; i++)
	{
		nodes[i].next = &nodes[i+1];
	}
	nodes[i].next = NULL;
	
	fifo.head = &nodes[0];
	fifo.tail = &nodes[fifo_size - 1];
	
	fifo.nodes = nodes;
	*ppfifo = &fifo;

	return 0;
}

int destroy_fifo(struct fifo_t * pfifo)
{
	if(pfifo->nodes != NULL)
		free(pfifo->nodes);
	pthread_mutex_destroy(&pfifo->lock);
	pfifo->head = NULL;
	pfifo->tail = NULL;
}

int traverse(struct fifo_t * pfifo)
{
	struct pcm_node_t * p = NULL;
	p =	pfifo->head;
	while(p != NULL)
	{
		printf("p->pcm[0] : %x , head : %p, tail : %p , next : %p\n",p->pcm[0] , pfifo->head , pfifo->tail , p->next);
		p = p->next;
	}
}

int in_fifo(struct fifo_t * pfifo , struct pcm_node_t * pnode)
{
	struct pcm_node_t * p ;
	if(pfifo == NULL || pnode == NULL)
		return -1;

	pthread_mutex_lock(&pfifo->lock);
	p = pfifo->tail;
	if(p == NULL)
		pfifo->head = pfifo->tail = pnode;
	else
	{
		p->next = pnode;
		pfifo->tail = pnode;
	}
	pnode->next = NULL;

	pthread_mutex_unlock(&pfifo->lock);
	return 0;
}

struct pcm_node_t * out_fifo(struct fifo_t * pfifo)
{
	struct pcm_node_t * p ;
	if(pfifo == NULL)
		return NULL;

	pthread_mutex_lock(&pfifo->lock);
	p = pfifo->head;
	if(p == NULL)
	{
		pthread_mutex_unlock(&pfifo->lock);
		return NULL;
	}
	else
		(NULL == (pfifo->head = p->next)) ? pfifo->tail = NULL : NULL  ;

	pthread_mutex_unlock(&pfifo->lock);
	return p;
}

struct pcm_node_t * must_out(struct fifo_t * pfifo_mem , struct fifo_t * pfifo_data)
{
	struct pcm_node_t * p ;
	p = out_fifo(pfifo_mem);
	if(p == NULL)
		p = out_fifo(pfifo_data);
	//if(p == NULL)
	//	return NULL;
	return p;
}

