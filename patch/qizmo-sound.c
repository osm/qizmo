/* Linux sound compatibility driver for Qizmo 2.91. */

/*
 * Qizmo still owns sound loading, mixing, voice encoding, and voice
 * decoding. This library only emulates the OSS /dev/dsp interface expected
 * by Qizmo and connects the final PCM stream to ALSA.
 *
 * Because Qizmo is a 32-bit program, this file declares only the small part
 * of the system ABI it needs instead of relying on distribution-specific
 * 32-bit development packages. ALSA is loaded from the installed 32-bit
 * libasound.so.2 at runtime with dlopen() and dlsym().
 */

typedef unsigned int size_t;
typedef unsigned long pthread_t;
typedef struct _snd_pcm snd_pcm_t;
typedef long snd_pcm_sframes_t;
typedef unsigned long snd_pcm_uframes_t;
typedef void *(*thread_entry_t)(void *);

extern int close(int);
extern int dlclose(void *);
extern void *dlopen(const char *, int);
extern void *dlsym(void *, const char *);
extern int ftruncate(int, long);
extern int ioctl(int, unsigned long, ...);
extern int memfd_create(const char *, unsigned int);
extern void *mmap(void *, size_t, int, int, int, long);
extern int munmap(void *, size_t);
extern int open(const char *, int, ...);
extern int pthread_create(
	pthread_t *, const void *, thread_entry_t, void *);
extern int pthread_join(pthread_t, void **);
extern int usleep(unsigned int);

/* Fixed addresses in the supported Qizmo 2.91 Linux executable. */

#define QIZMO_CAPTURE_READ_SLOT       ((void **)0x080cda58)
#define QIZMO_CAPTURE_AVAILABLE_SLOT  ((void **)0x080cda5c)
#define QIZMO_CAPTURE_SHUTDOWN_SLOT   ((void **)0x080cda60)
#define QIZMO_CAPTURE_START_SLOT      ((void **)0x080cda64)
#define QIZMO_CAPTURE_STOP_SLOT       ((void **)0x080cda68)

#define QIZMO_OPEN_GOT_ENTRY   ((void **)0x080d1d84)
#define QIZMO_IOCTL_GOT_ENTRY  ((void **)0x080d1c20)
#define QIZMO_CLOSE_GOT_ENTRY  ((void **)0x080d1da0)

#define QIZMO_ORIGINAL_CAPTURE_READ ((void *)0x08074b08)

/*
 * The original OSS backend keeps these values outside its device structure.
 * Qizmo closes and reopens /dev/dsp whenever the game/voice playback mode
 * is changed, but the values are not reset by its shutdown function. Qizmo
 * then compares that stale state with the newly opened device's playback
 * counter. Our replacement counter intentionally starts at zero for every
 * ALSA stream, so reset Qizmo's matching bookkeeping at the same boundary.
 */
#define QIZMO_DMA_WRITE_OFFSET   ((unsigned int *)0x0815bca0)
#define QIZMO_DMA_QUEUED_BYTES   ((unsigned int *)0x0815bca4)
#define QIZMO_DMA_PREVIOUS_BYTES ((unsigned int *)0x0815bcb0)
#define QIZMO_DMA_COUNT_INFO     ((void *)0x0815bccc)

/* OSS, ALSA, mmap, and dynamic-loader constants used by the bridge. */

#define OSS_DEVICE_PATH   "/dev/dsp"
#define ALSA_LIBRARY_NAME "libasound.so.2"
#define ALSA_DEVICE_NAME  "default"

#define PLAYBACK_FRAGMENTS 16
#define PLAYBACK_FRAGMENT_BYTES 2048
#define PLAYBACK_RING_BYTES \
	(PLAYBACK_FRAGMENTS * PLAYBACK_FRAGMENT_BYTES)
#define PLAYBACK_CHANNELS 2
#define PLAYBACK_SAMPLE_BYTES 2
#define PLAYBACK_FRAME_BYTES \
	(PLAYBACK_CHANNELS * PLAYBACK_SAMPLE_BYTES)
#define PLAYBACK_DEFAULT_RATE_HZ 11025
#define PLAYBACK_LATENCY_US 10000
#define PLAYBACK_FALLBACK_PERIOD_HZ 100
#define PLAYBACK_START_POLL_US 1000

#define CAPTURE_CHANNELS 1
#define CAPTURE_SAMPLE_BYTES 2
#define CAPTURE_RATE_HZ 8000
#define CAPTURE_LATENCY_US 40000

#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_SHARED 1
#define MAP_FAILED ((void *)-1)

#define MFD_CLOEXEC 1

#define RTLD_NOW 2

#define SND_PCM_STREAM_PLAYBACK 0
#define SND_PCM_STREAM_CAPTURE  1
#define SND_PCM_NONBLOCK        1
#define SND_PCM_ACCESS_RW_INTERLEAVED 3
#define SND_PCM_FORMAT_S16_LE          2

#define PCM_ENABLE_OUTPUT 2
#define DSP_CAP_TRIGGER   0x00001000
#define DSP_CAP_MMAP      0x00002000

#define SNDCTL_DSP_SPEED       0xc0045002UL
#define SNDCTL_DSP_STEREO      0xc0045003UL
#define SNDCTL_DSP_SAMPLESIZE  0xc0045005UL
#define SNDCTL_DSP_GETOSPACE   0x8010500cUL
#define SNDCTL_DSP_GETCAPS     0x8004500fUL
#define SNDCTL_DSP_SETTRIGGER  0x40045010UL
#define SNDCTL_DSP_GETOPTR     0x800c5012UL

struct audio_buf_info {
	int fragments;
	int fragstotal;
	int fragsize;
	int bytes;
};

struct count_info {
	int bytes;
	int blocks;
	int ptr;
};

/* Dynamically resolved libasound entry points. */

struct alsa_api {
	void *library_handle;
	int (*pcm_open)(snd_pcm_t **, const char *, int, int);
	int (*pcm_close)(snd_pcm_t *);
	int (*pcm_set_params)(snd_pcm_t *, int, int, unsigned int,
		unsigned int, int, unsigned int);
	int (*pcm_start)(snd_pcm_t *);
	int (*pcm_drop)(snd_pcm_t *);
	int (*pcm_get_params)(snd_pcm_t *, snd_pcm_uframes_t *,
		snd_pcm_uframes_t *);
	int (*pcm_delay)(snd_pcm_t *, snd_pcm_sframes_t *);
	snd_pcm_sframes_t (*pcm_writei)(snd_pcm_t *, const void *,
		snd_pcm_uframes_t);
	snd_pcm_sframes_t (*pcm_readi)(snd_pcm_t *, void *,
		snd_pcm_uframes_t);
	snd_pcm_sframes_t (*pcm_avail_update)(snd_pcm_t *);
	int (*pcm_recover)(snd_pcm_t *, int, int);
};

/* Runtime state. */

static struct alsa_api alsa_api;

/* OSS playback bridge. */
static int oss_fd = -1;
static unsigned char *playback_ring;
static int playback_rate_hz = PLAYBACK_DEFAULT_RATE_HZ;
static unsigned long long total_submitted_bytes;
static unsigned long long total_played_bytes;
static unsigned int submitted_bytes_snapshot;
static unsigned int played_bytes_snapshot;
static int playback_running;
static pthread_t playback_thread;
static int playback_thread_started;
static unsigned int playback_period_frames;
static snd_pcm_t *playback_pcm;

/* Microphone capture. */
static snd_pcm_t *capture_pcm;

/* Small utilities. */

static int strings_equal(const char *left, const char *right)
{
	while (*left && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}

static void clear_bytes(void *data, unsigned int bytes)
{
	unsigned char *cursor = data;
	while (bytes--) {
		*cursor++ = 0;
	}
}

/* Playback-position bookkeeping shared by the worker and OSS callbacks. */

static unsigned long long calculate_played_total(
	unsigned long long previous_played_bytes,
	unsigned long long submitted_bytes,
	snd_pcm_sframes_t delay_frames)
{
	unsigned long long delayed_bytes;
	unsigned long long played_bytes;

	if (delay_frames < 0) {
		delay_frames = 0;
	}
	delayed_bytes = (unsigned long long)(unsigned long)delay_frames *
		PLAYBACK_FRAME_BYTES;
	if (delayed_bytes > submitted_bytes) {
		delayed_bytes = submitted_bytes;
	}
	played_bytes = submitted_bytes - delayed_bytes;
	if (played_bytes < previous_played_bytes) {
		return previous_played_bytes;
	}
	return played_bytes;
}

static int qizmo_dma_needs_resync(unsigned int played_bytes,
	unsigned int previous_bytes, unsigned int queued_bytes)
{
	long long current_position = (int)played_bytes;
	long long previous_position = (int)previous_bytes;
	long long remaining_bytes;

	/* Match Qizmo's signed comparison and ring-wrap handling. */
	if (current_position < previous_position) {
		current_position += PLAYBACK_RING_BYTES / 2;
	}
	remaining_bytes = (long long)(int)queued_bytes -
		(current_position - previous_position);
	return remaining_bytes < 0;
}

static unsigned int calculate_resync_offset(unsigned int submitted_bytes)
{
	unsigned int ring_offset = submitted_bytes % PLAYBACK_RING_BYTES;
	unsigned int aligned_offset;

	aligned_offset = ring_offset & ~(PLAYBACK_FRAME_BYTES - 1U);
	return (aligned_offset + PLAYBACK_FRAME_BYTES) %
		PLAYBACK_RING_BYTES;
}

/* Dynamic ALSA loading. */

#define LOAD_ALSA(member) do { \
	*(void **)(&alsa_api.member) = \
		dlsym(alsa_api.library_handle, "snd_" #member); \
	if (!alsa_api.member) { \
		goto failed; \
	} \
} while (0)

static int load_alsa_api(void)
{
	if (alsa_api.library_handle) {
		return 0;
	}

	alsa_api.library_handle = dlopen(ALSA_LIBRARY_NAME, RTLD_NOW);
	if (!alsa_api.library_handle) {
		return -1;
	}
	LOAD_ALSA(pcm_open);
	LOAD_ALSA(pcm_close);
	LOAD_ALSA(pcm_set_params);
	LOAD_ALSA(pcm_start);
	LOAD_ALSA(pcm_drop);
	LOAD_ALSA(pcm_get_params);
	LOAD_ALSA(pcm_delay);
	LOAD_ALSA(pcm_writei);
	LOAD_ALSA(pcm_readi);
	LOAD_ALSA(pcm_avail_update);
	LOAD_ALSA(pcm_recover);
	return 0;

failed:
	dlclose(alsa_api.library_handle);
	clear_bytes(&alsa_api, sizeof(alsa_api));
	return -1;
}

/* Playback. */

static void stop_playback(void)
{
	__atomic_store_n(&playback_running, 0, __ATOMIC_RELEASE);
	if (playback_pcm) {
		alsa_api.pcm_drop(playback_pcm);
	}
	if (playback_thread_started) {
		pthread_join(playback_thread, 0);
		playback_thread_started = 0;
	}
	if (playback_pcm) {
		alsa_api.pcm_close(playback_pcm);
		playback_pcm = 0;
	}
}

static int recover_playback_stream(snd_pcm_sframes_t error_code)
{
	return alsa_api.pcm_recover(
		playback_pcm, (int)error_code, 1);
}

static void update_playback_progress(unsigned int written_frames)
{
	unsigned int submitted_snapshot;
	snd_pcm_sframes_t delay_frames = 0;

	/* Only the playback thread changes the full-width totals. */
	total_submitted_bytes +=
		written_frames * PLAYBACK_FRAME_BYTES;
	submitted_snapshot = (unsigned int)total_submitted_bytes;
	__atomic_store_n(&submitted_bytes_snapshot, submitted_snapshot,
		__ATOMIC_RELAXED);

	if (alsa_api.pcm_delay(playback_pcm, &delay_frames) < 0) {
		return;
	}
	total_played_bytes = calculate_played_total(
		total_played_bytes, total_submitted_bytes, delay_frames);
	__atomic_store_n(&played_bytes_snapshot,
		(unsigned int)total_played_bytes, __ATOMIC_RELEASE);
}

static int write_playback_frames(const unsigned char *sample_data,
	unsigned int frame_count)
{
	while (frame_count &&
		__atomic_load_n(&playback_running, __ATOMIC_ACQUIRE)) {
		snd_pcm_sframes_t written_frames;

		written_frames = alsa_api.pcm_writei(
			playback_pcm, sample_data,
			(snd_pcm_uframes_t)frame_count);

		if (written_frames < 0) {
			if (recover_playback_stream(written_frames) < 0) {
				return -1;
			}
			continue;
		}
		if (written_frames == 0) {
			return -1;
		}
		sample_data +=
			(unsigned int)written_frames * PLAYBACK_FRAME_BYTES;
		frame_count -= (unsigned int)written_frames;
		update_playback_progress((unsigned int)written_frames);
	}
	return 0;
}

static int write_playback_period(void)
{
	unsigned int period_bytes;
	unsigned int ring_offset;
	unsigned int contiguous_bytes;
	unsigned int wrapped_bytes;

	period_bytes = playback_period_frames * PLAYBACK_FRAME_BYTES;
	ring_offset = __atomic_load_n(&submitted_bytes_snapshot,
		__ATOMIC_RELAXED) % PLAYBACK_RING_BYTES;
	contiguous_bytes = PLAYBACK_RING_BYTES - ring_offset;
	if (contiguous_bytes > period_bytes) {
		contiguous_bytes = period_bytes;
	}
	if (write_playback_frames(playback_ring + ring_offset,
		contiguous_bytes / PLAYBACK_FRAME_BYTES) < 0) {
		return -1;
	}
	if (contiguous_bytes == period_bytes) {
		return 0;
	}

	wrapped_bytes = period_bytes - contiguous_bytes;
	return write_playback_frames(playback_ring,
		wrapped_bytes / PLAYBACK_FRAME_BYTES);
}

static void *playback_thread_main(void *unused)
{
	(void)unused;

	/*
	 * Qizmo starts the OSS DMA trigger before its first mixer update.
	 * Do not consume the zero-filled mmap ring during that gap: the
	 * original copy callback increments this counter only after the
	 * first mixed block is completely in the ring.
	 */
	while (__atomic_load_n(&playback_running, __ATOMIC_ACQUIRE) &&
		__atomic_load_n(QIZMO_DMA_QUEUED_BYTES,
			__ATOMIC_ACQUIRE) == 0) {
		usleep(PLAYBACK_START_POLL_US);
	}

	while (__atomic_load_n(&playback_running, __ATOMIC_ACQUIRE)) {
		if (write_playback_period() < 0) {
			break;
		}
	}
	__atomic_store_n(&playback_running, 0, __ATOMIC_RELEASE);
	return 0;
}

static int open_playback_stream(void)
{
	if (load_alsa_api() < 0) {
		return -1;
	}
	if (alsa_api.pcm_open(&playback_pcm, ALSA_DEVICE_NAME,
		SND_PCM_STREAM_PLAYBACK, 0) < 0) {
		playback_pcm = 0;
		return -1;
	}
	if (alsa_api.pcm_set_params(playback_pcm, SND_PCM_FORMAT_S16_LE,
		SND_PCM_ACCESS_RW_INTERLEAVED, PLAYBACK_CHANNELS,
		(unsigned int)playback_rate_hz, 1,
		PLAYBACK_LATENCY_US) < 0) {
		alsa_api.pcm_close(playback_pcm);
		playback_pcm = 0;
		return -1;
	}
	return 0;
}

static unsigned int choose_playback_period(void)
{
	snd_pcm_uframes_t buffer_frames = 0;
	snd_pcm_uframes_t period_frames = 0;

	if (alsa_api.pcm_get_params(
		playback_pcm, &buffer_frames, &period_frames) < 0 ||
		period_frames == 0 ||
		period_frames * PLAYBACK_FRAME_BYTES >
			PLAYBACK_RING_BYTES) {
		period_frames = (snd_pcm_uframes_t)playback_rate_hz /
			PLAYBACK_FALLBACK_PERIOD_HZ;
	}
	if (period_frames == 0) {
		period_frames = 1;
	}
	return (unsigned int)period_frames;
}

static void reset_playback_progress(void)
{
	total_submitted_bytes = 0;
	total_played_bytes = 0;
	__atomic_store_n(&submitted_bytes_snapshot, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&played_bytes_snapshot, 0, __ATOMIC_RELAXED);
}

static int start_playback_thread(void)
{
	__atomic_store_n(&playback_running, 1, __ATOMIC_RELEASE);
	if (pthread_create(
		&playback_thread, 0, playback_thread_main, 0) != 0) {
		__atomic_store_n(&playback_running, 0, __ATOMIC_RELEASE);
		stop_playback();
		return -1;
	}
	playback_thread_started = 1;
	return 0;
}

static int start_playback(void)
{
	if (__atomic_load_n(&playback_running, __ATOMIC_ACQUIRE)) {
		return 0;
	}
	if (playback_pcm) {
		stop_playback();
	}
	if (open_playback_stream() < 0) {
		return -1;
	}
	playback_period_frames = choose_playback_period();
	reset_playback_progress();
	return start_playback_thread();
}

/* Microphone capture callbacks installed into Qizmo. */

static void close_capture_stream(void)
{
	if (capture_pcm) {
		alsa_api.pcm_drop(capture_pcm);
		alsa_api.pcm_close(capture_pcm);
		capture_pcm = 0;
	}
}

static void recover_capture_stream(snd_pcm_sframes_t error_code)
{
	if (alsa_api.pcm_recover(
		capture_pcm, (int)error_code, 1) >= 0) {
		alsa_api.pcm_start(capture_pcm);
	}
}

static void clear_capture_samples(short *samples, int sample_count)
{
	if (sample_count <= 0) {
		return;
	}
	clear_bytes(samples,
		(unsigned int)sample_count * CAPTURE_SAMPLE_BYTES);
}

static int capture_read(short *samples, int sample_count)
{
	snd_pcm_sframes_t received_frames;

	if (!capture_pcm || sample_count <= 0) {
		clear_capture_samples(samples, sample_count);
		return 0;
	}
	received_frames = alsa_api.pcm_readi(capture_pcm, samples,
		(snd_pcm_uframes_t)sample_count);
	if (received_frames < 0) {
		recover_capture_stream(received_frames);
		received_frames = 0;
	}
	if (received_frames < sample_count) {
		clear_capture_samples(samples + received_frames,
			sample_count - (int)received_frames);
	}
	return (int)received_frames;
}

static int capture_available(void)
{
	snd_pcm_sframes_t frames;
	if (!capture_pcm) {
		return 0;
	}
	frames = alsa_api.pcm_avail_update(capture_pcm);
	if (frames < 0) {
		recover_capture_stream(frames);
		return 0;
	}
	return (int)frames;
}

static int capture_start(void)
{
	if (capture_pcm) {
		return 1;
	}
	if (load_alsa_api() < 0) {
		return 0;
	}
	if (alsa_api.pcm_open(&capture_pcm, ALSA_DEVICE_NAME,
		SND_PCM_STREAM_CAPTURE, SND_PCM_NONBLOCK) < 0) {
		capture_pcm = 0;
		return 0;
	}
	if (alsa_api.pcm_set_params(capture_pcm, SND_PCM_FORMAT_S16_LE,
		SND_PCM_ACCESS_RW_INTERLEAVED, CAPTURE_CHANNELS,
		CAPTURE_RATE_HZ, 1, CAPTURE_LATENCY_US) < 0) {
		close_capture_stream();
		return 0;
	}
	if (alsa_api.pcm_start(capture_pcm) < 0) {
		close_capture_stream();
		return 0;
	}
	return 1;
}

/* OSS /dev/dsp emulation installed into Qizmo's libc call sites. */

static void reset_qizmo_dma(void)
{
	*QIZMO_DMA_WRITE_OFFSET = 0;
	*QIZMO_DMA_QUEUED_BYTES = 0;
	*QIZMO_DMA_PREVIOUS_BYTES = 0;
	clear_bytes(QIZMO_DMA_COUNT_INFO, sizeof(struct count_info));
}

static void report_output_space(struct audio_buf_info *info)
{
	info->fragments = PLAYBACK_FRAGMENTS;
	info->fragstotal = PLAYBACK_FRAGMENTS;
	info->fragsize = PLAYBACK_FRAGMENT_BYTES;
	info->bytes = PLAYBACK_RING_BYTES;
}

static void resync_qizmo_dma_if_needed(unsigned int played_bytes,
	unsigned int submitted_bytes)
{
	/*
	 * Qizmo's progress callback clamps an exhausted queue to zero.
	 * Unlike its copy callback, it does not move the mmap write cursor.
	 * That was safe when OSS hardware consumed the mmap ring directly.
	 * Our ALSA staging queue has a separate consumer cursor, so
	 * realign here before Qizmo mixes the replacement block.
	 */
	if (!qizmo_dma_needs_resync(played_bytes,
		*QIZMO_DMA_PREVIOUS_BYTES, *QIZMO_DMA_QUEUED_BYTES)) {
		return;
	}
	*QIZMO_DMA_WRITE_OFFSET = calculate_resync_offset(submitted_bytes);
}

static void report_output_position(struct count_info *info)
{
	unsigned int played_bytes;
	unsigned int submitted_bytes;

	played_bytes = __atomic_load_n(&played_bytes_snapshot,
		__ATOMIC_ACQUIRE);
	submitted_bytes = __atomic_load_n(&submitted_bytes_snapshot,
		__ATOMIC_ACQUIRE);

	resync_qizmo_dma_if_needed(played_bytes, submitted_bytes);

	/*
	 * bytes is the hardware-consumption clock. ptr is the next mmap
	 * byte the worker will copy, which can be ahead by the ALSA
	 * queue size.
	 */
	info->bytes = (int)played_bytes;
	info->blocks = 0;
	info->ptr = (int)(submitted_bytes % PLAYBACK_RING_BYTES);
}

static int open_oss_device(void)
{
	if (load_alsa_api() < 0 || oss_fd >= 0) {
		return -1;
	}

	oss_fd = memfd_create("qizmo-sound", MFD_CLOEXEC);
	if (oss_fd < 0) {
		return -1;
	}
	if (ftruncate(oss_fd, PLAYBACK_RING_BYTES) < 0) {
		close(oss_fd);
		oss_fd = -1;
		return -1;
	}
	playback_ring = mmap(0, PLAYBACK_RING_BYTES,
		PROT_READ | PROT_WRITE, MAP_SHARED, oss_fd, 0);
	if (playback_ring == MAP_FAILED) {
		close(oss_fd);
		oss_fd = -1;
		playback_ring = 0;
		return -1;
	}
	clear_bytes(playback_ring, PLAYBACK_RING_BYTES);
	reset_qizmo_dma();
	return oss_fd;
}

static int qizmo_open_hook(const char *path, int flags, int mode)
{
	if (!strings_equal(path, OSS_DEVICE_PATH)) {
		return open(path, flags, mode);
	}
	return open_oss_device();
}

static int qizmo_ioctl_hook(int descriptor, unsigned long request,
	void *argument)
{
	if (descriptor != oss_fd) {
		return ioctl(descriptor, request, argument);
	}

	switch (request) {
	case SNDCTL_DSP_STEREO:
		return argument && *(int *)argument == 1 ? 0 : -1;
	case SNDCTL_DSP_SAMPLESIZE:
		return argument && *(int *)argument == 16 ? 0 : -1;
	case SNDCTL_DSP_SPEED:
		if (!argument || *(int *)argument <= 0) {
			return -1;
		}
		playback_rate_hz = *(int *)argument;
		return 0;
	case SNDCTL_DSP_GETCAPS:
		*(int *)argument = DSP_CAP_TRIGGER | DSP_CAP_MMAP;
		return 0;
	case SNDCTL_DSP_GETOSPACE:
		report_output_space(argument);
		return 0;
	case SNDCTL_DSP_SETTRIGGER:
		if (*(int *)argument & PCM_ENABLE_OUTPUT) {
			return start_playback();
		}
		stop_playback();
		return 0;
	case SNDCTL_DSP_GETOPTR:
		report_output_position(argument);
		return 0;
	default:
		return -1;
	}
}

static int close_oss_device(void)
{
	stop_playback();
	if (playback_ring) {
		munmap(playback_ring, PLAYBACK_RING_BYTES);
		playback_ring = 0;
	}
	close(oss_fd);
	oss_fd = -1;
	return 0;
}

static int qizmo_close_hook(int descriptor)
{
	if (descriptor != oss_fd) {
		return close(descriptor);
	}
	return close_oss_device();
}

/* Hook installation. */

static int is_supported_qizmo(void)
{
	return *QIZMO_CAPTURE_READ_SLOT == QIZMO_ORIGINAL_CAPTURE_READ;
}

static void install_capture_hooks(void)
{
	*QIZMO_CAPTURE_READ_SLOT = capture_read;
	*QIZMO_CAPTURE_AVAILABLE_SLOT = capture_available;
	*QIZMO_CAPTURE_SHUTDOWN_SLOT = close_capture_stream;
	*QIZMO_CAPTURE_START_SLOT = capture_start;
	*QIZMO_CAPTURE_STOP_SLOT = close_capture_stream;
}

static void install_oss_hooks(void)
{
	*QIZMO_OPEN_GOT_ENTRY = qizmo_open_hook;
	*QIZMO_IOCTL_GOT_ENTRY = qizmo_ioctl_hook;
	*QIZMO_CLOSE_GOT_ENTRY = qizmo_close_hook;
}

__attribute__((constructor))
static void initialize_audio_bridge(void)
{
	/* Only patch the expected Qizmo memory layout. */
	if (!is_supported_qizmo()) {
		return;
	}

	install_capture_hooks();
	install_oss_hooks();
}
