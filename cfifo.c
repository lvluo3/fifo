#include <stdio.h>
#include <pthread.h>

#define FIFO_SIZE 16

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

int __init_fifo(int fifo_size)
{
	static struct node_t nodes[FIFO_SIZE];
	//static struct node_t nodes[fifo_size];

	int i;
	static struct fifo_t fifo;
	pthread_mutex_init(&fifo.lock , NULL);
	for(i = 0 ; i < FIFO_SIZE - 1 ; i++)
	{
		nodes[i].pcm[0]= i+6;
		nodes[i].next = &nodes[i+1];
	}
	nodes[i].next = NULL;

	fifo.head = &nodes[0];
	fifo.head = &nodes[FIFO_SIZE - 1];	
}

int traverse(struct fifo_t * pfifo)
{
	struct node_t * p = NULL;
	p =	pfifo->head;
	while(p != NULL)
	{
		printf("p->pcm[0] : %x , head : %p, tail : %p , next : %p\n",p->pcm[0] , pfifo->head , pfifo->tail , p->next);
		p = p->next;
	}
}

int in_fifo(struct fifo_t * pfifo , struct node_t * pnode)
{
	struct node_t * p ;
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

struct node_t * out_fifo(struct fifo_t * pfifo)
{
	struct node_t * p ;
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

struct node_t * must_out(struct fifo_t * pfifo_mem , struct fifo_t * pfifo_data)
{
	struct node_t * p ;
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
	struct node_t * p;
	struct node_t * a[3];
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
		printf("a[i] : %p , a[i]->next %p , a[i]->pcm[0] %d \n",
				a[i] , a[i]->next , a[i]->pcm[0]);
	}

	while((p = out_fifo(pfifo)) != NULL)
		printf("p->buf[0] : %x\n",p->pcm[0]);


	return 0;
}
