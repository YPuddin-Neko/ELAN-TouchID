/* Shared macOS ELAN transport and capture, with an in-memory diagnostic CLI.
 * 0c1a protocol adapted from libfprint's elan driver:
 * Copyright (C) 2017 Igor Filatov, LGPL-2.1-or-later. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include "libusb.h"
#include "elanpress-match.h"
#include "ElanCaptureEvents.h"
static void (*capture_status)(const char*)=NULL;
static int (*capture_should_cancel)(void)=NULL;
static void (*capture_observer)(const ElanpressTouchStats*,int,int)=NULL;
static unsigned capture_timeout_seconds=90;
static void (*capture_event)(ElanCaptureEvent)=NULL;
static ElanCaptureResult capture_last_result=ElanCapturePending;
static void captureEvent(ElanCaptureEvent event){if(capture_event)capture_event(event);}
static void progress(const char*s){if(capture_status)capture_status(s);else puts(s);}
static volatile sig_atomic_t cancelled=0;
static void interrupt(int s){cancelled=1;}
typedef struct {
    libusb_context *ctx;
    libusb_device_handle *h;
    int claimed, w, hgt;
    uint16_t pid, firmware;
    unsigned char *raw;
    unsigned short *bg;
} Sensor;

static int io(Sensor *s, unsigned char ep, unsigned char *b, int len) {
    int n = 0;
    int r = libusb_bulk_transfer(s->h, ep, b, len, &n, 3000);
    if (r || n != len) {
        fprintf(stderr, "USB通信失败 %02x: %s (%d/%d)\n",
                ep, libusb_error_name(r), n, len);
        return 0;
    }
    return 1;
}

static int command(Sensor *s, unsigned a, unsigned b) {
    unsigned char c[2] = {a, b};
    return io(s, 0x01, c, sizeof(c));
}

static int frameWithDelay(Sensor *s, unsigned short *out, useconds_t delayUs) {
    if (cancelled) return 0;
    /* 0c6e requires a status read before each image request. */
    if (s->pid == 0x0c6e) {
        unsigned char status;
        if (!command(s, 0x40, 0x13) || !io(s, 0x83, &status, 1)) return 0;
    }
    if (!command(s, 0x00, 0x09) ||
        !io(s, 0x82, s->raw, s->w * s->hgt * 2)) return 0;
    elanpress_rotate_frame(s->raw, out, s->w, s->hgt);
    if (delayUs) usleep(delayUs);
    return !cancelled;
}

static int frameCalibration(Sensor *s, unsigned short *out) {
    return frameWithDelay(s, out, 5000);
}

static int frame(Sensor *s, unsigned short *out) {
    return frameWithDelay(s, out, 15000);
}

static void close_sensor(Sensor *s) {
    if (s->h && s->claimed) {
        command(s, 0x00, 0x0b);
        libusb_release_interface(s->h, 0);
    }
    if (s->h) libusb_close(s->h);
    if (s->ctx) libusb_exit(s->ctx);
    if (s->raw) { memset(s->raw, 0, s->w * s->hgt * 2); free(s->raw); }
    if (s->bg) { memset(s->bg, 0, s->w * s->hgt * 2); free(s->bg); }
    memset(s, 0, sizeof(*s));
}

static int open_sensor(Sensor *s) {
    unsigned char dim[4], firmware[2];
    int r = libusb_init(&s->ctx);
    if (r) { fprintf(stderr, "USB初始化失败: %s\n", libusb_error_name(r)); return 0; }
    libusb_device **devices = NULL;
    ssize_t count = libusb_get_device_list(s->ctx, &devices);
    if (count < 0) { fprintf(stderr, "无法枚举USB设备\n"); goto failed; }
    for (ssize_t i = 0; i < count; ++i) {
        struct libusb_device_descriptor d;
        if (libusb_get_device_descriptor(devices[i], &d)) continue;
        if (d.idVendor != 0x04f3 || (d.idProduct != 0x0c1a && d.idProduct != 0x0c6e)) continue;
        r = libusb_open(devices[i], &s->h);
        if (r) fprintf(stderr, "无法打开 ELAN %04x:%04x: %s\n", d.idVendor, d.idProduct, libusb_error_name(r));
        else s->pid = d.idProduct;
        break;
    }
    libusb_free_device_list(devices, 1);
    if (!s->h) { progress("未能打开 ELAN 指纹设备，请检查 USB 连接。"); goto failed; }
    r = libusb_claim_interface(s->h, 0);
    if (r) { fprintf(stderr, "无法占用指纹接口: %s\n", libusb_error_name(r)); goto failed; }
    s->claimed = 1;
    if (!command(s, 0x40, 0x19) || !io(s, 0x83, firmware, 2) ||
        !command(s, 0x00, 0x0c) || !io(s, 0x83, dim, 4)) goto failed;
    s->firmware = ((uint16_t)firmware[0] << 8) | firmware[1];
    s->w = dim[2];
    s->hgt = dim[0];
    if ((s->w & 1) && (s->hgt & 1)) { ++s->w; ++s->hgt; }
    if (!s->w || !s->hgt || (s->pid == 0x0c6e && (s->w != 150 || s->hgt != 52))) {
        fprintf(stderr, "设备报告的图像尺寸不受支持: %dx%d\n", s->w, s->hgt);
        goto failed;
    }
    s->raw = calloc((size_t)s->w * s->hgt, 2);
    s->bg = calloc((size_t)s->w * s->hgt, 2);
    if (!s->raw || !s->bg || !command(s, 0x00, 0x0b)) goto failed;
    printf("ELAN 04f3:%04x firmware=0x%04x size=%dx%d\n", s->pid, s->firmware, s->w, s->hgt);
    return 1;
failed:
    close_sensor(s);
    return 0;
}
static int calibrate(Sensor*s){int size=s->w*s->hgt;unsigned short*tmp=calloc(size,2);unsigned long*sum=calloc(size,sizeof(unsigned long));if(!tmp||!sum){free(tmp);free(sum);return 0;}progress("请把手指移开，正在采集背景…");for(int i=0;i<12;i++){if(!frame(s,tmp)){free(tmp);free(sum);return 0;}for(int j=0;j<size;j++)sum[j]+=tmp[j];}for(int j=0;j<size;j++)s->bg[j]=sum[j]/12;free(tmp);free(sum);return 1;}
static int check_background(void) {
    Sensor s = {0};
    int ok = open_sensor(&s) && calibrate(&s);
    if (ok) {
        unsigned char response[2];
        unsigned long sum = 0;
        unsigned low = 65535, high = 0;
        for (int i = 0; i < s.w * s.hgt; ++i) {
            sum += s.bg[i];
            if (s.bg[i] < low) low = s.bg[i];
            if (s.bg[i] > high) high = s.bg[i];
        }
        unsigned mean = sum / (s.w * s.hgt);
        printf("Background mean=%u min=%u max=%u\n",mean,low,high);
        ok = command(&s,0x40,0x24) && io(&s,0x83,response,2);
        if (ok) {
            unsigned calibration = (response[0] << 8) | response[1];
            printf("Calibration mean=%u delta=%d (libfprint recalibrates above 500)\n",calibration,abs((int)mean-(int)calibration));
        }
    }
    close_sensor(&s);
    return ok ? 0 : 1;
}
static double frame_difference(const unsigned short *a, const unsigned short *b, int size) {
    double sum = 0, sum2 = 0;
    for (int i = 0; i < size; ++i) {
        double d = (double)a[i] - b[i];
        sum += d;
        sum2 += d * d;
    }
    double mean = sum / size;
    return sum2 / size - mean * mean;
}

static double capture_milliseconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC,&t);
    return t.tv_sec*1000.0+t.tv_nsec/1000000.0;
}

/* Averaging a moving press smears ridge detail. Use its most stable three frames. */
static unsigned char *stable_image(GSList *frames, int count, Sensor *s, double *motion) {
    GSList *best = frames;
    double least = INFINITY;
    for (GSList *a = frames; a && a->next && a->next->next; a = a->next) {
        double d = frame_difference(a->data, a->next->data, s->w * s->hgt) +
                   frame_difference(a->next->data, a->next->next->data, s->w * s->hgt);
        if (d < least) { least = d; best = a; }
    }
    if (count < 3 || !best || !best->next || !best->next->next) return NULL;
    GSList third = {best->next->next->data, NULL};
    GSList second = {best->next->data, &third};
    GSList first = {best->data, &second};
    *motion = sqrt(least / 2.0);
    return elanpress_process_frames(&first, 3, s->bg, s->w * s->hgt);
}

static ElanpressFeatures *captureWithReaderOptionsUntil(Sensor *s, int (*readFrame)(Sensor *, unsigned short *),
                                                        double deadline, int requiredClear) {
    int size = s->w * s->hgt;
    unsigned short *tmp = calloc(size, sizeof(*tmp));
    GSList *list = NULL;
    int n = 0, clear = 0, started = 0, remindedLift = 0;
    int singlePress = s->pid == 0x0c1a;
    int frameCount = singlePress ? 1 : 10;
    double entered = capture_milliseconds(), landed = 0, processing = 0;
    ElanpressFeatures *features = NULL;
    capture_last_result = ElanCapturePending;
    if (!tmp) { capture_last_result = ElanCaptureAllocationError; return NULL; }
    if (requiredClear >= 4) {
        progress("请先松开手指，等待采集提示。");
        captureEvent(ElanCaptureAwaitRelease);
    }
    while (!cancelled && capture_milliseconds() < deadline) {
        if(capture_should_cancel && capture_should_cancel()) { capture_last_result = ElanCaptureCancelled; break; }
        if (!readFrame(s, tmp)) { capture_last_result = cancelled ? ElanCaptureCancelled : ElanCaptureDeviceError; break; }
        if (cancelled || (capture_should_cancel && capture_should_cancel())) {
            capture_last_result = ElanCaptureCancelled; break;
        }
        if (capture_milliseconds() >= deadline) { capture_last_result = ElanCaptureTimedOut; break; }
        ElanpressTouchStats stats;
        int touched = elanpress_frame_has_touch(tmp, s->bg, size, &stats);
        int releaseClean = !touched && (requiredClear >= 4 || stats.coverage < 0.03);
        int reportTouched = requiredClear >= 4 ? touched : (touched && (started || clear >= requiredClear));
        if (capture_observer && (reportTouched || releaseClean || requiredClear >= 4))
            capture_observer(&stats, reportTouched, clear);
        if (!started) {
            if (!touched) {
                if (releaseClean && ++clear == requiredClear) {
                    progress(singlePress ? "请轻放手指。" : "请轻放手指并保持不动，看到松开提示后再抬起。");
                    captureEvent(ElanCaptureReady);
                }
                continue;
            }
            if (clear < requiredClear) {
                clear = 0;
                if (requiredClear > 0 && requiredClear < 4 && !remindedLift && capture_milliseconds() - entered >= 200) {
                    remindedLift = 1;
                    captureEvent(ElanCaptureAwaitRelease);
                }
                continue;
            }
            started = 1;
            landed = capture_milliseconds();
            captureEvent(ElanCaptureTouchDetected);
        }
        if (!touched) {
            if (singlePress) {
                progress("手指抬起过早，请重新轻放，等提示后再松开。");
                capture_last_result = ElanCaptureImageRejected;
                captureEvent(ElanCaptureTooShort);
                break;
            }
            while (list) {
                GSList *next = list->next;
                memset(list->data,0,size*sizeof(*tmp));
                free(list->data); free(list); list=next;
            }
            n=0; clear=1; started=0;
            continue;
        }
        /* Let contact settle before taking one image; averaging a moving
         * finger over several seconds blurs the local ridge features. */
        if (singlePress && capture_milliseconds() - landed < 200) continue;
        GSList *node = calloc(1, sizeof(*node));
        if (!node) { capture_last_result = ElanCaptureAllocationError; break; }
        node->data = malloc(size * sizeof(*tmp));
        if (!node->data) { free(node); capture_last_result = ElanCaptureAllocationError; break; }
        memcpy(node->data, tmp, size * sizeof(*tmp));
        node->next = list;
        list = node;
        if (++n < frameCount) continue;
        processing = capture_milliseconds();
        unsigned char *img = elanpress_process_frames(list,n,s->bg,size);
        if (img) {
            double quality = elanpress_image_quality(img, size);
            features = elanpress_image_features(img, s->w, s->hgt);
            printf("采集：尺寸 %dx%d，对比度 %.1f，帧数 %d，特征点 %u。\n",
                   s->w, s->hgt, quality, n, features ? features->n : 0);
            printf("CAPTURE pid=%04x frames=%d hold_ms=%.0f process_ms=%.1f\n",
                   s->pid,n,processing-landed,capture_milliseconds()-processing);
            if (cancelled || (capture_should_cancel && capture_should_cancel()) || capture_milliseconds() >= deadline) {
                if (features) {
                    memset(features->kp, 0, features->n * sizeof(*features->kp));
                    elanpress_features_free(features); features = NULL;
                }
                capture_last_result = cancelled || (capture_should_cancel && capture_should_cancel())
                    ? ElanCaptureCancelled : ElanCaptureTimedOut;
            } else if (quality < ELANPRESS_MIN_QUALITY_STDDEV || !features ||
                features->n < ELANPRESS_MATCH_MIN_PAIRS) {
                if (features) elanpress_features_free(features);
                features = NULL;
                progress("指纹图像不清晰，请松开后重新轻放。");
                capture_last_result = ElanCaptureImageRejected;
                captureEvent(ElanCaptureLowQuality);
            } else {
                progress("采集完成，请松开手指。");
                capture_last_result = ElanCaptureSucceeded;
                captureEvent(ElanCaptureSampleReady);
            }
            memset(img, 0, size);
            free(img);
        } else capture_last_result = ElanCaptureAllocationError;
        break;
    }
    while (list) {
        GSList *next = list->next;
        memset(list->data, 0, size * sizeof(*tmp));
        free(list->data);
        free(list);
        list = next;
    }
    memset(tmp, 0, size * sizeof(*tmp));
    free(tmp);
    if (cancelled || (capture_should_cancel && capture_should_cancel())) capture_last_result = ElanCaptureCancelled;
    else if (capture_last_result == ElanCapturePending ||
             ((capture_last_result == ElanCaptureSucceeded || capture_last_result == ElanCaptureImageRejected) &&
              capture_milliseconds() >= deadline)) capture_last_result = ElanCaptureTimedOut;
    if (features && capture_last_result != ElanCaptureSucceeded) {
        memset(features->kp, 0, features->n * sizeof(*features->kp));
        elanpress_features_free(features); features = NULL;
    }
    return features;
}

static ElanpressFeatures *captureWithReaderUntil(Sensor *s, int (*readFrame)(Sensor *, unsigned short *), double deadline) {
    return captureWithReaderOptionsUntil(s, readFrame, deadline, 4);
}
static ElanpressFeatures *captureWithReader(Sensor *s, int (*readFrame)(Sensor *, unsigned short *)) {
    return captureWithReaderUntil(s, readFrame, capture_milliseconds() + capture_timeout_seconds * 1000.0);
}
static ElanpressFeatures *captureAfterRelease(Sensor *s, int alreadyClear) {
    return captureWithReaderOptionsUntil(s, frame, capture_milliseconds() + capture_timeout_seconds * 1000.0, alreadyClear ? 0 : 1);
}
static ElanpressFeatures *captureUntil(Sensor *s, double deadline) { return captureWithReaderUntil(s, frame, deadline); }
static ElanpressFeatures *capture(Sensor *s) { return captureWithReader(s, frame); }
static unsigned match(ElanpressFeatures*f,ElanpressFeatures**templates,int n){unsigned best=0;for(int i=0;i<n;i++){unsigned score=elanpress_match_features(f,templates[i]);if(score>best)best=score;}return best;}
static int pause_prompt(const char*msg){puts(msg);fflush(stdout);int c;do{c=getchar();if(c==EOF)return 0;}while(c!='\n');return !cancelled;}
static int self_test_size(int w, int h) {
    int size = w * h;
    unsigned char *a = malloc(size), *b = malloc(size), *blank = calloc(size, 1);
    if (!a || !b || !blank) { free(a); free(b); free(blank); return 1; }
    uint32_t x = 13, y = 999;
    for (int i = 0; i < size; ++i) {
        x = x * 1664525u + 1013904223u;
        y = y * 1664525u + 1013904223u;
        a[i] = x >> 24; b[i] = y >> 24;
    }
    ElanpressFeatures *fa = elanpress_image_features(a, w, h);
    ElanpressFeatures *fb = elanpress_image_features(b, w, h);
    ElanpressFeatures *fz = elanpress_image_features(blank, w, h);
    unsigned same = elanpress_match_features(fa, fa);
    unsigned other = elanpress_match_features(fa, fb);
    unsigned zero = elanpress_match_features(fa, fz);
    int ok = fa && fa->n >= 12 && same >= 12 && other < 12 && zero == 0;
    printf("Matcher %dx%d: points=%u same=%u unrelated=%u blank=%u\n", w, h, fa ? fa->n : 0, same, other, zero);
    elanpress_features_free(fa); elanpress_features_free(fb); elanpress_features_free(fz);
    free(a); free(b); free(blank);
    return ok ? 0 : 1;
}
static int self_test(void) {
    return self_test_size(144, 64) | self_test_size(150, 52);
}
int main(int argc,char**argv){if(argc==2&&!strcmp(argv[1],"--self-test"))return self_test();if(argc==2&&!strcmp(argv[1],"--check-background"))return check_background();if(argc==2&&!strcmp(argv[1],"--probe")){Sensor s={0};int ok=open_sensor(&s);close_sensor(&s);return ok?0:1;}setbuf(stdout,NULL);signal(SIGINT,interrupt);signal(SIGTERM,interrupt);Sensor s={0};ElanpressFeatures*t[8]={0};int rc=1;
 puts("ELAN 指纹录入与匹配实验\n模板仅在本次运行内存中保存。按 Control+C 可以停止。");if(!pause_prompt("先把手指移开，按回车开始背景采集。"))goto end;if(!open_sensor(&s)||!calibrate(&s))goto end;
 puts("第一阶段：使用同一根手指，录入 8 次。前4次保持指腹中心位置，后4次只小幅移动。每次采集后松开。");for(int i=0;i<8;i++){printf("\n录入 %d/8\n",i+1);for(int tries=0;tries<3&&!t[i]&&!cancelled;tries++)t[i]=capture(&s);if(!t[i])goto end;}
 if(!pause_prompt("\n第二阶段：仍然用刚才那根手指，验证 3 次。准备好后按回车。"))goto end;int genuine=0,impostor=0;
 for(int i=0;i<3;i++){printf("\n同指测试 %d/3\n",i+1);ElanpressFeatures*f=capture(&s);if(!f)goto end;unsigned score=match(f,t,8);printf("匹配特征对：%u；参考阈值 %d；%s\n",score,ELANPRESS_MATCH_MIN_PAIRS,score>=ELANPRESS_MATCH_MIN_PAIRS?"判为匹配":"判为不匹配");if(score>=ELANPRESS_MATCH_MIN_PAIRS)genuine++;elanpress_features_free(f);}
 if(!pause_prompt("\n第三阶段：换成没有录入的其他手指，验证 3 次。准备好后按回车。"))goto end;
 for(int i=0;i<3;i++){printf("\n其他手指测试 %d/3\n",i+1);ElanpressFeatures*f=capture(&s);if(!f)goto end;unsigned score=match(f,t,8);printf("匹配特征对：%u；%s\n",score,score>=ELANPRESS_MATCH_MIN_PAIRS?"出现误接受":"判为不匹配");if(score>=ELANPRESS_MATCH_MIN_PAIRS)impostor++;elanpress_features_free(f);}
 printf("\n实验结果：同指接受 %d/3；其他手指误接受 %d/3。\n",genuine,impostor);rc=(genuine==3&&impostor==0)?0:2;
end:for(int i=0;i<8;i++)if(t[i])elanpress_features_free(t[i]);close_sensor(&s);puts("本次内存模板已释放。没有修改密码或登录配置。");return rc;}
