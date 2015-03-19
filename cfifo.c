#include <stdio.h>
#include "cfifo.h"

int init_empty_fifo(struct fifo_t ** ppfifo)
{
	static struct fifo_t fifo;
	pthread_mutex_init(&fifo.lock , NULL);
	*ppfifo = &fifo;

	return 0;
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

int main()
{
	struct fifo_t * pfifo;
	struct pcm_node_t * p;
	struct pcm_node_t * a[3];
	int i = 0;
	int ret;

	init_fifo(&pfifo,3);
	traverse(pfifo);
	for(i = 0 ; (a[i] = out_fifo(pfifo)) != NULL ; i++)
		traverse(pfifo);
#if 0
	while(1)
	{
		printf("----------------\n");
		traverse(pfifo);
		a[i] = out_fifo(pfifo);
		if(NULL == a[i])
			break;
		i++;
	}
	for(i = 2 ; 0 <= i ; i--)
	{
		printf("+++++++++++++++++++\n");
		ret = in_fifo(pfifo,a[i]);
		traverse(pfifo);
	}
#endif
	printf("+++++++++++++++++++\n");
	for( i= 2 ; 0 <= i ; i --)
	{
		printf("tail %p ,head %p\n",pfifo->tail , pfifo->head);
		in_fifo(pfifo , a[i]);
		traverse(pfifo);
	}
	printf("----------------\n");

	for(i = 0 ; i < 3 ; i ++)
	{
		printf("a[i] : %p , a[i]->next %p , a[i]->pcm[0] %c \n",
				a[i] , a[i]->next , a[i]->pcm[0]);
	}

	while((p = out_fifo(pfifo)) != NULL)
		printf("p->buf[0] : %c\n",p->pcm[0]);


	return 0;
}
