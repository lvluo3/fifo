#include "cfifo.h"

int main()
{
	struct fifo_t * pfifo;
	struct pcm_node_t * p;
	struct pcm_node_t * a[10];
	int i = 0;
	int ret;

	init_fifo(&pfifo,3);
	traverse(pfifo);

	for(i = 0 ; (a[i] = out_fifo(pfifo)) != NULL ; i++)
		traverse(pfifo);

#if 0

	for(i = 0 ; i < 4 ; i ++)
	{
		a[i] = out_fifo(pfifo);
		traverse(pfifo);
	}
#endif

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
	for(i = 0 ; i < 3 ; i ++)
	{
		printf("a[i] : %p , a[i]->next %p , a[i]->pcm[0] %c \n",
				a[i] , a[i]->next , a[i]->pcm[0]);
	}


	for( i= 2 ; 0 <= i ; i --)
	{
		printf("tail %p ,head %p\n",pfifo->tail , pfifo->head);
		in_fifo(pfifo , a[i]);
		traverse(pfifo);
	}
	printf("----------------\n");


	while((p = out_fifo(pfifo)) != NULL)
		printf("p->buf[0] : %c\n",p->pcm[0]);


	return 0;
}
