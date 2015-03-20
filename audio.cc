#include <inttypes.h>
#include <samplerate.h>
#include <faac.h>
#include <faad.h>
#include <signal.h>
#include "thread.h"
#include "udp.h"
#include "rec_file.h"
#include "codec_rtp.h"
#include "audio_trans.h"
#include "audio.h"
#include "cvt.h"
#include "mp2_codec.h"
//#include <ortp/ortp.h>

#define FRAME_MAX_LEN 1024*5
#define BUFFER_MAX_LEN 1024*1024

struct ReSampleContext;
struct AVResampleContext;

typedef struct ReSampleContext ReSampleContext;


enum AVSampleFormat {
	AV_SAMPLE_FMT_NONE = -1,
	AV_SAMPLE_FMT_U8,          ///< unsigned 8 bits
	AV_SAMPLE_FMT_S16,         ///< signed 16 bits
	AV_SAMPLE_FMT_S32,         ///< signed 32 bits
	AV_SAMPLE_FMT_FLT,         ///< float
	AV_SAMPLE_FMT_DBL,         ///< double

	AV_SAMPLE_FMT_U8P,         ///< unsigned 8 bits, planar
	AV_SAMPLE_FMT_S16P,        ///< signed 16 bits, planar
	AV_SAMPLE_FMT_S32P,        ///< signed 32 bits, planar
	AV_SAMPLE_FMT_FLTP,        ///< float, planar
	AV_SAMPLE_FMT_DBLP,        ///< double, planar

	AV_SAMPLE_FMT_NB           ///< Number of sample formats. DO NOT USE if linking dynamically
};

/**
 *  Initialize audio resampling context.
 *
 * @param output_channels  number of output channels
 * @param input_channels   number of input channels
 * @param output_rate      output sample rate
 * @param input_rate       input sample rate
 * @param sample_fmt_out   requested output sample format
 * @param sample_fmt_in    input sample format
 * @param filter_length    length of each FIR filter in the filterbank relative to the cutoff frequency
 * @param log2_phase_count log2 of the number of entries in the polyphase filterbank
 * @param linear           if 1 then the used FIR filter will be linearly interpolated
 * between the 2 closest, if 0 the closest will be used
 * @param cutoff           cutoff frequency, 1.0 corresponds to half the output sampling rate
 * @return allocated ReSampleContext, NULL if error occurred
 */
extern "C" ReSampleContext *av_audio_resample_init(int output_channels, int input_channels,
		int output_rate, int input_rate,
		enum AVSampleFormat sample_fmt_out,
		enum AVSampleFormat sample_fmt_in,
		int filter_length, int log2_phase_count,
		int linear, double cutoff);

extern "C" int audio_resample(ReSampleContext *s, short *output, short *input, int nb_samples);


extern "C" void wx_g729aencode(char * inbuf , int in_len,char * outbuf , int * out_len);
extern "C" void wx_g729adecode(char * inbuf , int in_len,char * outbuf , int * out_len);

extern "C" void g711_enc_init();
extern "C" void g711_enc(char* pcm_buf , int pcm_len , char * g711_buf , int * g711_len);

int audio_read_fd =-1;
CRecFile audio_rec;
extern std::string audio_pipe_file;
extern sig_atomic_t balm_quit; 

int get_one_ADTS_frame(unsigned char *buffer, size_t buf_size, unsigned char *data, size_t * data_size);
void channel21(unsigned char *pcm_stereo, unsigned char *pcm_mono, int mono_len);
void ShowConfig(faacEncConfigurationPtr config);

// BUF前预留8个字节，真实的mp2_buf为指针的8个字节后
static void packet_ws_mp2(uint8_t * mp2_buf, uint16_t mp2_buf_len)
{
	static short seq = 0;
	static int index = 0;

	if (index % 1024 == 0) {
		seq = 0;
		index = 0;
	}

	seq += 1;
	seq %= 128;
	index += 1;

	*(uint16_t *) mp2_buf = mp2_buf_len;
	*(uint16_t *) (mp2_buf + 2) = seq;
	*(uint32_t *) (mp2_buf + 4) = index;
	return;
}

int write_audio_file(char * str , const char * buf , int len)
{
	int 		  ret ;
	static FILE * pfd = NULL;
	if(pfd == NULL)
	{
		pfd = fopen(str , "wb");
		if(pfd == NULL)
		{
			perror("fopen err ");
			exit(-1);
		}
	}
	ret = fwrite(buf , 1 , len , pfd);
	if(ret != len)
	{
		perror("fwrite err ");
	}
	fflush(pfd);
}

int write_audio_file1(char * str , const char * buf , int len)
{
	int 		  ret ;
	static FILE * pfd = NULL;
	if(pfd == NULL)
	{
		pfd = fopen(str , "wb");
		if(pfd == NULL)
		{
			perror("fopen err ");
			exit(-1);
		}
	}
	ret = fwrite(buf , 1 , len , pfd);
	if(ret != len)
	{
		perror("fwrite err ");
	}
	fflush(pfd);
}

void thread_proc audio_cvt_proc(void *arg)
{
	cvt_t *cvt_info = (cvt_t *) arg;

	CUdp *audio_udp = new CUdp(cvt_info->src_ip, cvt_info->src_port);
	int audio_fd = open(audio_pipe_file.c_str(), O_WRONLY);
	if (audio_fd < 0) {
		fprintf(stderr, "open audio_pipe error, exit!\n");
		exit(1);
	}

	struct sockaddr_in peer_addr;
	memset(&peer_addr, 0, sizeof(peer_addr));

	//resample
	int re_err = 0;

	SRC_DATA redata;
	//SRC_STATE* re = src_new(SRC_LINEAR, 1, &re_err);
	SRC_STATE *re = src_new(3, 1, &re_err);

	// 设置变换率:目的/源
	// -------------------------------
	char *ptr = NULL;
	ptr = strchr(cvt_info->src_string, ',');
	if (ptr)
		cvt_info->src_sam_rate = atoi(ptr + 1);
	else
		cvt_info->src_sam_rate = opt::get_au_rate(cvt_info->src_st);

	ptr = strchr(cvt_info->dst_string, ',');
	if (ptr)
		cvt_info->dst_sam_rate = atoi(ptr + 1);
	else
		cvt_info->dst_sam_rate = opt::get_au_rate(cvt_info->dst_st);

	//--------------------------------

	redata.src_ratio = (double)(cvt_info->dst_sam_rate) / (cvt_info->src_sam_rate);

	fprintf(stderr, "ratio: %f, source audio samplerate: %d, dst audio samplerate:%d.\n", 
			redata.src_ratio, cvt_info->src_sam_rate, cvt_info->dst_sam_rate);

	float pcmbuf_f[1024 * 16];
	float resampleOutbuf_f[1024 * 16];

	unsigned char in_buf[1024 * 8] = { 0 };
	unsigned char pcm_buf[1024 * 16] = { 0 };
	int32_t in_len = 0;
	int pcm_len = 0;

	//init resample
	ReSampleContext * m_pReSmpCtx = NULL;

	if(cvt_info->src_st == AU_AAC)
	{
		m_pReSmpCtx = av_audio_resample_init(1,2,cvt_info->dst_sam_rate,cvt_info->src_sam_rate * 2,
				AV_SAMPLE_FMT_S16,AV_SAMPLE_FMT_S16,16,10,0,1.0);
	}
	else if(cvt_info->dst_st == AU_G711A)
	{
		m_pReSmpCtx = av_audio_resample_init(1,1,cvt_info->dst_sam_rate + 0,cvt_info->src_sam_rate,
				AV_SAMPLE_FMT_S16,AV_SAMPLE_FMT_S16,16,10,0,1.0);
	}
	else
	{
		m_pReSmpCtx = av_audio_resample_init(1,1,cvt_info->dst_sam_rate,cvt_info->src_sam_rate,
				AV_SAMPLE_FMT_S16,AV_SAMPLE_FMT_S16,16,10,0,1.0);
	}


	//HMP2DEC hDec = MP2_decode_init();
	Mp2_Codec mp2_decode;
	mp2_decode.decode_init();

	// aad init
	NeAACDecHandle decoder = 0;
	NeAACDecConfigurationPtr config;
	NeAACDecFrameInfo frame_info;
	unsigned long samplerate;
	unsigned char channels;

	unsigned char frame[FRAME_MAX_LEN];
	size_t size = 0;
	int aacd_is_init = 0;

	decoder = NeAACDecOpen();

	printf("cvt_info->src_st :%d.\r\n", cvt_info->src_st);
	while (true) {
		in_len = audio_udp->receive(in_buf, 2048, &peer_addr);
#if	0
		// 录音,进来的声音
		audio_rec.rec("audio-in.org", (const char*)in_buf + sizeof(rtp_hdr_t), 
				in_len - sizeof(rtp_hdr_t));
#endif

		if (cvt_info->src_st == AU_MP2) {
			// 采样率: 22050 单声道 精度: 16BIT
			// 输入长度: 217? 216?  输出长度: 1152*2 = 2304
			//MP2_decode_frame(hDec, pcm_buf, (UINT32 *)&pcm_len, 
			//      in_buf + WS_AUDIO_HEAD_LEN, in_len - WS_AUDIO_HEAD_LEN);
			mp2_decode.decode(in_buf + WS_AUDIO_HEAD_LEN, in_len - WS_AUDIO_HEAD_LEN,
					pcm_buf, &pcm_len);


		}else if (cvt_info->src_st == AU_G729A) {
			pcm_len = 0;
			wx_g729adecode((char*)in_buf + sizeof(rtp_hdr_t),in_len - sizeof(rtp_hdr_t),(char*)pcm_buf,&pcm_len);

		} else if (cvt_info->src_st == AU_AAC || (cvt_info->src_st == AU_AACLD)) {
			unsigned char *pcm_stereo = NULL;

			//write_audio_file1("audio-in.aacld",(const char*)in_buf + sizeof(rtp_hdr_t),in_len - sizeof(rtp_hdr_t));
			// 收第一个包,根据包进行识别初始化
			if (aacd_is_init == 0) {
				/* Set configuration */
				config = NeAACDecGetCurrentConfiguration(decoder);

				//define is AAC-LC , config this is HE-AAC,HE-AACv2
				config->defObjectType = LC;//(cvt_info->src_st == AU_AACLD) ? LD_DEC_CAP : MAIN_DEC_CAP;
				//config->defObjectType = ER_LC;
				/*
				 *config->defSampleRate = 22050;
				 *config->outputFormat = outputFormat;
				 *config->downMatrix = downMatrix;
				 *config->dontUpSampleImplicitSBR = 1;
				 */
				NeAACDecSetConfiguration(decoder, config);
				get_one_ADTS_frame(in_buf + sizeof(rtp_hdr_t),
						in_len - sizeof(rtp_hdr_t), frame, &size);
				NeAACDecInit(decoder, frame, size, &samplerate, &channels);
				printf("aac ---- samplerate %d, channels %d , src_sam %d\n",
						(int)samplerate, channels , cvt_info->src_sam_rate);
				aacd_is_init = 1;
				continue;
			}
			if (get_one_ADTS_frame(in_buf + sizeof(rtp_hdr_t),
						in_len - sizeof(rtp_hdr_t), frame, &size) < 0) {
				fprintf(stderr, "get_one_ADTS_frame error.\n");
				continue;
			}

			pcm_stereo = (unsigned char *)NeAACDecDecode(decoder, &frame_info, frame, size);
			pcm_len = frame_info.samples * frame_info.channels;// / 2;
			memcpy(pcm_buf,pcm_stereo,pcm_len);

			//channel21(pcm_stereo, pcm_buf, pcm_len);

			//write_audio_file("aacld-audio-in.pcm", (const char*)pcm_buf, pcm_len);
		} else {
			rtp_hdr_t *rtp_head = (rtp_hdr_t *) in_buf;
			// 先做自动识别
			if (rtp_head->pt == 0)
				audio_convert(G711U2PCM, in_buf + sizeof(rtp_hdr_t),
						in_len - sizeof(rtp_hdr_t), 8, pcm_buf, pcm_len, 16);
			else if (rtp_head->pt == 8)	// pt== 8
				audio_convert(G711A2PCM, in_buf + sizeof(rtp_hdr_t),
						in_len - sizeof(rtp_hdr_t), 8, pcm_buf, pcm_len, 16);
			else if (cvt_info->src_st == AU_G711A)
				audio_convert(G711A2PCM, in_buf + sizeof(rtp_hdr_t),
						in_len - sizeof(rtp_hdr_t), 8, pcm_buf, pcm_len, 16);
			else if (cvt_info->src_st == AU_G711U)
				audio_convert(G711U2PCM, in_buf + sizeof(rtp_hdr_t),
						in_len - sizeof(rtp_hdr_t), 8, pcm_buf, pcm_len, 16);
			else
				fprintf(stderr, "error audio-in format: rtp payload(%d).\n", rtp_head->pt);
		}

#if	0
		// 录音,进来的声音
		audio_rec.rec("audio-in.pcm", (const char *)pcm_buf, pcm_len);
#endif

		// 根据重采样算出变换后的PCM长度，22050采样对应882字节
		// samplerate * bits/8 * channels = total bytes per sec
		// dst_pcm_size = total bytes / send packets per sec
#if 1
		if(pcm_len != 0)
		{
			int inchannels = cvt_info->src_st == AU_AAC ? 2 : 1;
			int outchannels = 1;
			int resam_len = 0;
			char resam_buf[1024 * 128];

			int resamplenum = audio_resample(m_pReSmpCtx,(short*)resam_buf,(short*)pcm_buf,pcm_len / ((inchannels) * 2)/*samples*/);
			resam_len = resamplenum * 2 * (outchannels);
			write(audio_fd, resam_buf, resam_len);
		}

#else
		// G711 每秒50帧
		int dst_pcm_size = pcm_len * cvt_info->dst_sam_rate / cvt_info->src_sam_rate;
		dst_pcm_size += dst_pcm_size % 2;	// 835.92 --> 836
		//fprintf(stderr, " %d \n", dst_pcm_size);

		//resample
		src_short_to_float_array((short *)pcm_buf, pcmbuf_f, pcm_len);

		redata.data_in = pcmbuf_f;
		redata.data_out = resampleOutbuf_f;
		redata.input_frames_used = 0;
		redata.output_frames_gen = 0;
		redata.end_of_input = 0;
		redata.input_frames = pcm_len;
		redata.output_frames = dst_pcm_size;

		src_process(re, &redata);
		src_float_to_short_array(resampleOutbuf_f, (short *)pcm_buf, dst_pcm_size);

		//              audio_rec.rec("audio-out.pcm", (const char *)pcm_buf, dst_pcm_size);

		write(audio_fd, pcm_buf, dst_pcm_size);
#endif
	}
	close(audio_fd);
	//MP2_decode_close(hDec);
	NeAACDecClose(decoder);
	delete audio_udp;
}
#include <sys/time.h>
#include "pcmafifo.h"
#include "cfifo.h"


typedef struct {
	stream_type_t type;
	int pcmlen;
} au_pcmlen_t;

au_pcmlen_t apl[] ={
	{AU_G711A , 320},
	{AU_G711U , 320},
	{AU_MP2 , 2304},
	{AU_AAC , 0},
	{AU_G729A , 480}
};

static int get_pcmlen_by_type(int type)
{
	for(int i = 0 ; i < 2 ; i ++)	
	{
		if(type == apl[i].type)
			return apl[i].type;
	}
	return 0;
}

void thread_proc audio_readn(void *arg)
{
	int pcm_len = 320;
	cvt_t * p	= (cvt_t *)arg;


	pcm_len = get_pcmlen_by_type(p->dst_st);
	for( ; ; )
	{
		if( balm_quit ) break;

		//wait();

		//struct fifo_node_t * node = mem_malloc();

		struct pcm_node_t * node = out_fifo((struct fifo_t *)p->p_memfifo);
		//if( node == NULL)
		while( node == NULL )
		{
			node = out_fifo((struct fifo_t*)p->p_pcmfifo);
			//	printf("----------------------------------------------------------------------mem_malloc() return NULL , no mem to malloc...\n");
			//	node = pcma_outfifo();
			//if(node != NULL)	
			//		mem_free(node);
			//continue;
		}

		//readn(audio_read_fd, node->buf , pcm_len);/////////////////////////

		readn(audio_read_fd, node->pcm , pcm_len);/////////////////////////
		//pcma_infifo(node);
		in_fifo((struct fifo_t*)p->p_pcmfifo, node);
	}

}

static int reinit_fifo_flag = 0;
static pthread_mutex_t fifoflag_lock = PTHREAD_MUTEX_INITIALIZER;

void * reinit_fifo(void * cvt_arg)
{
	socklen_t   len;
	char        mesg[128];
	int         recvlen;
	struct sockaddr_in  servaddr;//, cliaddr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&servaddr , 0 , sizeof(servaddr));
	servaddr.sin_family      = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port        = htons(SERV_PORT);

	Bind(sockfd, (SA *) &servaddr, sizeof(servaddr));

	for ( ; ; )
	{
		len = sizeof(struct sockaddr);//clilen;
		recvlen = Recvfrom(sockfd, mesg, 128 , 0, pcliaddr, &len);
		if(!memcmp(mesg , "reinit fifo : " , 14))
		{
			((cvt_t*)cvt_arg)->fifo_size = atoi(&mesg[14]);

			pthread_mutex_lock(&fifoflag_lock);
			reinit_fifo_flag = 1;
			pthread_mutex_unlock(&fifoflag_lock);
		}
	}
}


int start_audio_cvt(cvt_t * cvt_arg)
{
	CThread audio_cvt_thread;
	audio_cvt_thread.create(audio_cvt_proc, cvt_arg);

	CThread reinit_fifo_thread;
	reinit_fifo_thread.create(reinit_fifo, cvt_arg);

	cvt_arg->fifo_size = 15;
	init_empty_fifo((struct fifo_t **)&(cvt_arg->p_pcmfifo));
	init_fifo((struct fifo_t **)&(cvt_arg->p_memfifo) , cvt_arg->fifo_size);//p->fifo_size;

	if (cvt_arg->dst_st == AU_G711A)
	{
		//fifo_mem_init();
		CThread readn_thread;
		readn_thread.create(audio_readn, cvt_arg);
	}

	struct sockaddr_in dst_addr;
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_addr.s_addr = cvt_arg->dst_ip;
	dst_addr.sin_port = htons(cvt_arg->dst_port);

	CUdp *send_udp;
	if (cvt_arg->dst_bip == 0)
		send_udp = new CUdp;
	else {
		send_udp = new CUdp(cvt_arg->dst_bip, 0);
	}
	// 读入流数据
	audio_read_fd = open(audio_pipe_file.c_str(), O_RDONLY);
	if (audio_read_fd < 0) {
		fprintf(stderr, "open audio_pipe error, exit!\n");
		exit(1);
	}

	uint8_t	pcm_frame[2304] = {0};
	uint8_t	out_buf[4096] = {0};
	int out_len;


#if 0
	//init ortp
	RtpSession *session;
	char *ssrc;
	uint32_t user_ts=0;
	char dstip[128];
	struct in_addr indst_ip;
	int dstport = cvt_arg->dst_port;

	indst_ip.s_addr = cvt_arg->dst_ip;
	strcpy(dstip,inet_ntoa(indst_ip));
	printf("---inet_ntoa(cvt_arg->dst_ip) : %s \n",inet_ntoa(indst_ip));
	ortp_init();
	ortp_scheduler_init();
	ortp_set_log_level_mask(ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR);
	session=rtp_session_new(RTP_SESSION_SENDONLY);	

	rtp_session_set_scheduling_mode(session,1);
	rtp_session_set_blocking_mode(session,1);
	rtp_session_set_connected_mode(session,TRUE);
	rtp_session_set_remote_addr(session,(const char *)dstip,dstport);
	rtp_session_set_payload_type(session,8);//8 -> g711a 

	ssrc=getenv("SSRC");
	if (ssrc!=NULL) {
		printf("using SSRC=%i.\n",atoi(ssrc));
		rtp_session_set_ssrc(session,atoi(ssrc));
	}


	//create rtpSender obj
	//uint32_t dstIP = ntohl(cvt_arg->dst_ip);
	//int dstPort = cvt_arg->dst_port;
	//fprintf(stderr, "dstIP=%#x  dstPort=%d\n", dstIP, dstPort);
	//CRtpSender *rtpSender = new CRtpSender(1.0/8000.0, dstIP, dstPort);	
	//rtpSender->SetParamsForSendingG711(PAYLOAD_TYPE_PCMA);
#endif
	//calculate rtp time
	struct timeval tv1,tv2;

	//g711 encoder init
	g711_enc_init();

	//mp2decode err test
	FILE * mp2e_pfd;
	char   mp2e_buf[10240000] = {0};
	int    mp2e_len = 0;
	char * p_send = mp2e_buf;
	int    send_len = 0;

	mp2e_pfd = fopen("320byte.wav" , "rb");
	if(mp2e_pfd == NULL)
	{
		perror("fopen err ");
		exit(-1);
	}

	mp2e_len = fread(mp2e_buf,1,10240000 ,mp2e_pfd);
	printf("mp2e_len : %d \n",mp2e_len);
	if(mp2e_len < 44)
	{	
		printf("mp2e_len : %d < 44\n",mp2e_len);
		exit(-1);
	}

	p_send += 44;
	send_len = mp2e_len - 44;


	//HMP2ENC hEnc = MP2_encode_init(22050, 32000, 1);
	Mp2_Codec mp2_encode;
	mp2_encode.encode_init(22050, 32000, 1);

	uint64_t nInputSamples = 0;	// 得到每次调用编码时所应接收的原始数据长度
	uint64_t nMaxOutputBytes = 0;	// 得到每次调用编码时生成的AAC数据的最大长度
	faacEncHandle aacEncoder = faacEncOpen(cvt_arg->dst_sam_rate, 1, &nInputSamples, &nMaxOutputBytes);
	if (aacEncoder == NULL) {
		fprintf(stderr, "aac encoder init error.\n");
		exit(1);
	}
	fprintf(stderr, "samples = %ld , max_out_bytes = %ld \n", nInputSamples, nMaxOutputBytes);

	faacEncConfigurationPtr config;
	config = faacEncGetCurrentConfiguration(aacEncoder);

	config->version = 0;	//MPEG2;
	config->outputFormat = 1;	// ADTS_STREAM;
	config->inputFormat = 1;	// FAAC_INPUT_16BIT;
	config->aacObjectType = 2;	//LOW == 2 , MAIN == 1;
	config->useTns = 0;	//DEFAULT_TNS;
	config->shortctl = 0;	//SHORTCTL_NORMAL;
	config->allowMidside = 0;
	config->useLfe = 0;

	faacEncSetConfiguration(aacEncoder, config);
	//ShowConfig(config);
	printf("cvt_arg->dst_st : %d\n", cvt_arg->dst_st);
	sleep(1);
	while (true){
		if( balm_quit ) 
			break;

		if ( reinit_fifo_flag )
		{
			//reinit_fifo();
			//reinit_empty_fifo();
			//
			pthread_mutex_lock(&fifoflag_lock);
			reinit_fifo_flag = 0;
			pthread_mutex_unlock(&fifoflag_lock);
		}

		if (cvt_arg->dst_st == AU_MP2) {
			int pcm_len = 2304;
			readn(audio_read_fd, pcm_frame, pcm_len);
			//MP2_encode_frame(hEnc, (UINT32 *)&out_len, (UINT8 *)(out_buf + WS_AUDIO_HEAD_LEN), 
			//      pcm_len, (SINT16 *)pcm_frame);
			mp2_encode.encode((uint8_t *)pcm_frame, pcm_len,
					out_buf + WS_AUDIO_HEAD_LEN , &out_len);

			out_len += WS_AUDIO_HEAD_LEN;
			packet_ws_mp2(out_buf, (uint16_t) out_len);
			send_udp->send(out_buf, out_len, &dst_addr);
#if	0
			audio_rec.rec("audio-out.mp2", (const char *)out_buf + WS_AUDIO_HEAD_LEN, out_len);
#endif
		}
		// 需要进行wav->g711的变换
		// 进行rtp封包发送到目的地
		// out_len = wav2g711(resampleOutbuf, PCM_BUF_SIZE, out_buf + sizeof(rtp_hdr_t));
		else if (cvt_arg->dst_st == AU_G711U) {
			int pcm_len = 320;
			readn(audio_read_fd, pcm_frame, pcm_len);
			audio_convert(PCM2G711U, (uint8_t *) pcm_frame, pcm_len, 16,
					out_buf + sizeof(rtp_hdr_t), out_len, 8);
			out_len = CRtp::pack_g711(out_buf, out_len, 0);	// 数码视讯97
			send_udp->send(out_buf, out_len, &dst_addr);
			//                      audio_rec.rec("audio-out.g711u", (const char *)(out_buf + sizeof(rtp_hdr_t)), out_len);
		} else if (cvt_arg->dst_st == AU_G711A) {
			int pcm_len = 320;
			//readn(audio_read_fd, pcm_frame, pcm_len);/////////////////////////

#if 0							
			char stereo[1024];
			int i ,j=0;
			//int pcm_len = 640;
			for(i =0 ; i < 160 ;)
			{
				//stereo[j] = stereo[j+1] = *((unsigned short*)pcm_frame + i);
				stereo[j] = pcm_frame[i];
				stereo[j+1] = pcm_frame[i+1];
				stereo[j+2] = pcm_frame[i];
				stereo[j+3] = pcm_frame[i + 1];

				j += 4;
				i += 2;
			}
#endif

#if 0
			//g711_enc((char*)pcm_frame,320,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			g711_enc((char*)stereo,640,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			//write_audio_file1("ff.g711a",(char*)(out_buf + sizeof(rtp_hdr_t)),out_len);
			fprintf(stderr, "\n---------------------------\n");
			for (int i=0; i<out_len; i++)
			{
				fprintf(stderr, " %00x ", (char*)(out_buf + sizeof(rtp_hdr_t) + i) );
			}
			fprintf(stderr, "\n======================\n");

			fprintf(stderr, "Send G.711A packet! len=%d\n", out_len);
			if (!rtpSender->Send((out_buf + sizeof(rtp_hdr_t)), out_len)) //out_buf + sizeof(rtp_hdr_t), out_len))
			{
				fprintf(stderr, "[ERROR] Send g711A packet fail !\n");
			}
			else
			{
				fprintf(stderr, "ok\n");
			}
#elif 0
			///////////////////////////////////////////////////////////////
			g711_enc((char*)pcm_frame,320,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			//audio_convert(PCM2G711A, (uint8_t *) pcm_frame, pcm_len, 16,
			//				out_buf + sizeof(rtp_hdr_t), out_len, 8);
			out_len = CRtp::pack_g711(out_buf, out_len, 8);
			send_udp->send(out_buf, out_len, &dst_addr);
			write_audio_file1("rtp_g711a.in",(const char*)out_buf, out_len);
			//                      audio_rec.rec("audio-out.g711a", (const char *)(out_buf + sizeof(rtp_hdr_t)), out_len);
#else
			//audio_convert(PCM2G711A, (uint8_t *) pcm_frame, pcm_len, 16,
			//				out_buf + sizeof(rtp_hdr_t), out_len, 8);
			//g711_enc((char*)pcm_frame,320,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			//g711_enc((char*)p_send,320,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			//useconds_t usec = 0;
			//gettimeofday(&tv1,NULL);

			usleep(19850);
			static unsigned char repeat[256] = {0};//111
			//ooooooooooooooooooooooooooooooooooo    struct fifo_node_t * node = pcma_outfifo();
			struct pcm_node_t * node = out_fifo((struct fifo_t *)cvt_arg->p_pcmfifo); 
			if(node == NULL)
			{
				out_len = CRtp::pack_g711(repeat, 160, 8); //222
				send_udp->send(repeat, out_len, &dst_addr); //333
				//printf("it must != NULL!!!!!!! , this make jiter !!!!!\n");
				continue;
			}
			//g711_enc((char*)node->buf , 320 , (char*)(out_buf + sizeof(rtp_hdr_t)) , &out_len);
			audio_convert(PCM2G711A, (uint8_t *)node->pcm, pcm_len, 16,
					out_buf + sizeof(rtp_hdr_t), out_len, 8);
			out_len = CRtp::pack_g711(out_buf, out_len, 8);
			//time2;
			//gettimeofday(&tv2,NULL);
			//usec = tv2.tv_usec - tv1.tv_usec;
			//printf("usec %d\n" , usec);
			//usleep(5000 - usec);
			send_udp->send(out_buf, out_len, &dst_addr);
			memcpy(repeat, out_buf, out_len);
			//time1
			in_fifo((struct fifo_t *)cvt_arg->p_memfifo , node);
			//oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo mem_free(node);	
			//g711_enc((char*)p_send,320,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			//out_len = CRtp::pack_g711(out_buf, out_len, 8);
			//send_udp->send(out_buf, out_len, &dst_addr);

			//g711_enc((char*)p_send,320,(char*)(out_buf + sizeof(rtp_hdr_t)),&out_len);
			//out_len = CRtp::pack_g711(out_buf, out_len, 8);
			//send_udp->send(out_buf, out_len, &dst_addr);
			//rtp_session_send_with_ts(session,out_buf + sizeof(rtp_hdr_t), out_len,user_ts);
			//user_ts+=160;
			//if (user_ts%(160*50)==0){
			//		printf("Clock sliding of ?? miliseconds now\n");
			//		rtp_session_make_time_distorsion(session,0);

			//}

			/*if(send_len > 320)
			  {
			  p_send += 320;
			  send_len -= 320;
			  }
			  else
			  {
			  p_send = mp2e_buf + 44;
			  send_len = mp2e_len - 44;
			  }*/

#endif

		}else if (cvt_arg->dst_st == AU_G729A) {
			int pcm_len = 480;
			out_len = 0;
			readn(audio_read_fd, pcm_frame, pcm_len);
			wx_g729aencode((char *)pcm_frame,pcm_len , (char *)out_buf + sizeof(rtp_hdr_t) , &out_len);
			out_len = CRtp::pack_aac(out_buf, out_len, 18);
			send_udp->send(out_buf, out_len, &dst_addr);

		} else if (cvt_arg->dst_st == AU_AAC) {
			int pcm_len = nInputSamples * 2;	// 采样个数，16BIT，相当双字节
			readn(audio_read_fd, pcm_frame, pcm_len);

			out_len = faacEncEncode(aacEncoder, (int*) pcm_frame, nInputSamples, 
					out_buf + sizeof(rtp_hdr_t), nMaxOutputBytes);

			out_len = CRtp::pack_aac(out_buf, out_len, 97);
			send_udp->send(out_buf, out_len, &dst_addr);
			//                      audio_rec.rec("audio-out.aac", (const char *)(out_buf + sizeof(rtp_hdr_t)),
			//                               out_len - sizeof(rtp_hdr_t));
		}

	}
	//MP2_encode_close(hEnc);
	faacEncClose(aacEncoder);
	delete send_udp;
	return 0;
}

int get_one_ADTS_frame(unsigned char *buffer, size_t buf_size, unsigned char *data, size_t * data_size)
{
	size_t size = 0;

	if(!buffer || !data || !data_size )
	{
		return -1;
	}

	while(1)
	{
		if(buf_size  < 7 )
		{
			return -1;
		}

		if((buffer[0] == 0xff) && ((buffer[1] & 0xf0) == 0xf0) )
		{
			size |= ((buffer[3] & 0x03) << 11);	//   high 2 bit  
			size |= buffer[4] << 3;	//       middle 8 bit  
			size |= ((buffer[5] & 0xe0) >> 5);	//        low 3bit  
			break;
		}
		--buf_size;
		++buffer;
	}

	if(buf_size < size)
	{
		return -1;
	}

	memcpy(data, buffer, size);
	*data_size = size;

	return 0;
}

void channel21(unsigned char *pcm_stereo, unsigned char *pcm_mono, int mono_len)
{
	int i;
	int j = 0;
	for(i = 0; i < mono_len ; )
	{
		*(pcm_mono + i) = *(pcm_stereo + j);
		*(pcm_mono + i + 1) = *(pcm_stereo + j + 1);

		i += 2;
		j += 4;
	}
}

void ShowConfig(faacEncConfigurationPtr config)
{
	printf("version = %d \n", config->mpegVersion);
	printf("aacObjectType = %d \n", config->aacObjectType);

	printf("useTns = %d \n", config->useTns);
	printf("allowMidside = %d \n", config->allowMidside);
	printf("outputFormat = %d \n", config->outputFormat);
	printf("inputFormat = %d \n", config->inputFormat);

}
