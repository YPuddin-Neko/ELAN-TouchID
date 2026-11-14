/* In-memory capture comparison for the 0c1a port. */
#define main elan_original_diagnostic_main
#include "elan_match_test.c"
#undef main
#define VARIANTS 6
static const char *names[VARIANTS] = {"average21", "first9", "last9", "stable3", "single", "crop50"};

static int compare_press(Sensor *s, ElanpressFeatures **features) {
    enum { FRAME_COUNT = 24 };
    int size = s->w * s->hgt, clear = 0, captured = 0;
    unsigned short *frames = calloc(FRAME_COUNT * size, sizeof(*frames));
    unsigned short *tmp = calloc(size, sizeof(*tmp));
    GSList nodes[FRAME_COUNT];
    time_t deadline = time(NULL) + 90;
    double coverage = 0, delta = 0;
    int ok = 0;
    if (!frames || !tmp) goto done;
    puts("先松开手指；看到轻放提示后，保持同一个位置约 3 秒。");
    while (!cancelled && time(NULL) < deadline && captured < FRAME_COUNT) {
        if (!frame(s,tmp)) goto done;
        ElanpressTouchStats stats;
        int touch = elanpress_frame_has_touch(tmp,s->bg,size,&stats);
        if (!touch) {
            captured = 0;
            if (++clear == 4) puts("现在轻放手指，保持不动；等待松开提示。");
            continue;
        }
        if (clear < 4) { clear = 0; continue; }
        memcpy(frames + captured * size,tmp,size * sizeof(*tmp));
        captured++;
        coverage = stats.coverage;
        delta = stats.mean_delta;
    }
    if (captured != FRAME_COUNT) goto done;
    puts("采集完成，可以松开。正在比较图像处理方式…");
    for (int i = 0; i < FRAME_COUNT; ++i) {
        nodes[i].data = frames + (FRAME_COUNT-1-i)*size;
        nodes[i].next = i+1 < FRAME_COUNT ? &nodes[i+1] : NULL;
    }
    double motion = 0;
    unsigned char *images[VARIANTS] = {0};
    images[0] = elanpress_process_frames(nodes,FRAME_COUNT,s->bg,size);
    nodes[11].next = NULL;
    images[2] = elanpress_process_frames(nodes,12,s->bg,size);
    images[1] = elanpress_process_frames(&nodes[12],12,s->bg,size);
    nodes[11].next = &nodes[12];
    images[3] = stable_image(nodes,FRAME_COUNT,s,&motion);
    GSList single = {nodes[11].data,NULL};
    images[4] = elanpress_process_frames(&single,1,s->bg,size);
    int cropHeight = s->hgt < 50 ? s->hgt : 50;
    if (images[0]) {
        images[5] = malloc(s->w * cropHeight);
        if (images[5]) memcpy(images[5],images[0]+((s->hgt-cropHeight)/2)*s->w,s->w*cropHeight);
    }
    printf("Touch coverage=%.3f mean_delta=%.1f stable_motion=%.1f\n",coverage,delta,motion);
    ok = 1;
    for (int v = 0; v < VARIANTS; ++v) {
        int height = v == 5 ? cropHeight : s->hgt;
        if (images[v]) features[v] = elanpress_image_features(images[v],s->w,height);
        printf("  %s points=%u quality=%.1f\n",names[v],features[v]?features[v]->n:0,images[v]?elanpress_image_quality(images[v],s->w*height):0);
        if (!features[v]) ok=0;
        if (images[v]) { memset(images[v],0,s->w*height); free(images[v]); }
    }
    printf("  Same hold: first9/last9=%u average21/stable3=%u average21/single=%u\n",elanpress_match_features(features[1],features[2]),elanpress_match_features(features[0],features[3]),elanpress_match_features(features[0],features[4]));
done:
    if (frames) { memset(frames,0,FRAME_COUNT*size*sizeof(*frames)); free(frames); }
    if (tmp) { memset(tmp,0,size*sizeof(*tmp)); free(tmp); }
    return ok;
}
int main(void) {
    setbuf(stdout,NULL); signal(SIGINT,interrupt); signal(SIGTERM,interrupt);
    Sensor s={0}; ElanpressFeatures *samples[6][VARIANTS]={{0}}; int rc=1;
    puts("ELAN 采集比较：全部图像与模板仅在本次内存中处理。Control+C 停止。");
    if (!pause_prompt("移开手指，按回车开始背景采集。") || !open_sensor(&s) || !calibrate(&s)) goto done;
    puts("前 4 次用同一根手指，尽量让指腹中心落在同一位置，不刻意旋转。");
    for (int p=0;p<6&&!cancelled;++p) {
        if(p==4 && !pause_prompt("现在换成另一根未录入的手指，按回车后测试两次。")) goto done;
        printf("\n%s %d/%d\n",p<4?"同一手指":"另一手指",p<4?p+1:p-3,p<4?4:2);
        if(!compare_press(&s,samples[p]))goto done;
        if(p>0)for(int v=0;v<VARIANTS;++v){
            printf("  %s versus",names[v]);
            for(int j=0;j<p&&j<4;++j)printf(" sample%d=%u",j+1,elanpress_match_features(samples[p][v],samples[j][v]));
            putchar('\n');
        }
    }
    rc=0;
done:
    for(int p=0;p<6;++p)for(int v=0;v<VARIANTS;++v)elanpress_features_free(samples[p][v]);
    close_sensor(&s); puts("比较结束，图像和模板已释放。"); return rc;
}
