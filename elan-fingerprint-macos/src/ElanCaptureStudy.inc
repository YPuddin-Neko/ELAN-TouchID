/* Compare acquisition windows against the same saved templates and touches. */
enum { StudyFrames=24, StudyVariants=4, StudyPresses=6 };
static const char *studyNames[StudyVariants]={"single200", "first9", "last9", "average21"};

static double studyMilliseconds(void) {
    return capture_milliseconds();
}

static void studyFreeFeatures(ElanpressFeatures *f) {
    if(f)wipe(f->kp,f->n*sizeof(*f->kp));
    elanpress_features_free(f);
}

static unsigned char *studyWindow(const unsigned short *frames,int first,int count,Sensor *s) {
    if(first<0 || count<1 || first+count>StudyFrames)return NULL;
    GSList nodes[StudyFrames];
    size_t size=(size_t)s->w*s->hgt;
    for(int i=0;i<count;i++) {
        nodes[i].data=(void *)(frames+(first+count-1-i)*size);
        nodes[i].next=i+1<count?&nodes[i+1]:NULL;
    }
    return elanpress_process_frames(nodes,count,s->bg,(unsigned)size);
}

static int studyPress(int press,ElanpressFeatures **results) {
    size_t size=(size_t)sensor.w*sensor.hgt;
    unsigned short *frames=calloc(StudyFrames*size,sizeof(*frames));
    unsigned short *tmp=calloc(size,sizeof(*tmp));
    double times[StudyFrames]={0},start=studyMilliseconds(),landed=0;
    double clearDelta=0,minCoverage=1,maxCoverage=0,usbTotal=0;
    int n=0,clear=0,polls=0,lifted=0,ok=0;
    if(!frames || !tmp)goto done;
    puts("先松开手指，等到“可以按了”后再轻放；等提示松开。");
    while(!cancelled && studyMilliseconds()-start<30000 && n<StudyFrames) {
        double before=studyMilliseconds();
        if(!frame(&sensor,tmp))goto done;
        double now=studyMilliseconds();
        usbTotal+=now-before;polls++;
        ElanpressTouchStats stats;
        int touched=elanpress_frame_has_touch(tmp,sensor.bg,(unsigned)size,&stats);
        if(!touched) {
            if(n){lifted=1;break;}
            clearDelta=stats.mean_delta;
            if(++clear==4)puts("可以按了，轻放并保持这个位置。");
            continue;
        }
        if(clear<4){clear=0;continue;}
        if(!n)landed=now;
        memcpy(frames+n*size,tmp,size*sizeof(*tmp));
        times[n]=now-landed;n++;
        minCoverage=fmin(minCoverage,stats.coverage);
        maxCoverage=fmax(maxCoverage,stats.coverage);
    }
    if(cancelled)goto done;
    puts("可以松开了，正在比较。");
    printf("STUDY press=%d frames=%d lifted=%d wait_ms=%.0f hold_ms=%.0f frame_ms=%.1f clear_delta=%.1f coverage_min=%.3f coverage_max=%.3f\n",
           press+1,n,lifted,landed?landed-start:studyMilliseconds()-start,n?times[n-1]:0,
           polls?usbTotal/polls:0,clearDelta,minCoverage,maxCoverage);
    if(n<4){puts("这次没有采到足够的图像，继续下一次。");ok=1;goto done;}
    int single=0;
    while(single<n && times[single]<200)single++;
    int first[StudyVariants]={single,0,n-12,0};
    int count[StudyVariants]={1,12,12,24};
    for(int v=0;v<StudyVariants;v++) {
        if(first[v]<0 || first[v]+count[v]>n)continue;
        double before=studyMilliseconds();
        unsigned char *img=studyWindow(frames,first[v],count[v],&sensor);
        if(!img)continue;
        double quality=elanpress_image_quality(img,(unsigned)size);
        results[v]=elanpress_image_features(img,sensor.w,sensor.hgt);
        wipe(img,size);free(img);
        unsigned score=match(results[v],prints,printCount);
        int usable=results[v] && results[v]->n>=ELANPRESS_MATCH_MIN_PAIRS && quality>=ELANPRESS_MIN_QUALITY_STDDEV;
        printf("STUDY press=%d variant=%s acquired_ms=%.0f processing_ms=%.1f quality=%.1f points=%u score=%u usable=%d matched=%d\n",
               press+1,studyNames[v],times[first[v]+count[v]-1],studyMilliseconds()-before,
               quality,results[v]?results[v]->n:0,score,usable,usable&&score>=ELANPRESS_MATCH_MIN_PAIRS);
        if(!usable){studyFreeFeatures(results[v]);results[v]=NULL;}
    }
    printf("STUDY press=%d first_last_rms=%.1f first9_last9_score=%u\n",press+1,
           sqrt(frame_difference(frames,frames+(n-1)*size,(int)size)),
           elanpress_match_features(results[1],results[2]));
    ok=1;
done:
    if(frames){wipe(frames,StudyFrames*size*sizeof(*frames));free(frames);}
    if(tmp){wipe(tmp,size*sizeof(*tmp));free(tmp);}
    return ok;
}

static int captureStudySelfTest(void) {
    Sensor s={.w=144,.hgt=64};
    size_t size=(size_t)s.w*s.hgt;
    unsigned short *frames=calloc(StudyFrames*size,sizeof(*frames));
    s.bg=calloc(size,sizeof(*s.bg));
    if(!frames || !s.bg){free(frames);free(s.bg);return 1;}
    uint32_t seed=13;
    for(size_t i=0;i<size;i++) {
        seed=seed*1664525u+1013904223u;
        s.bg[i]=8000;
        for(int n=0;n<StudyFrames;n++)frames[n*size+i]=9000+(seed>>20);
    }
    ElanpressFeatures *features[StudyVariants]={0};
    int first[]={3,0,12,0},count[]={1,12,12,24},ok=1;
    for(int v=0;v<StudyVariants;v++) {
        unsigned char *img=studyWindow(frames,first[v],count[v],&s);
        if(img){features[v]=elanpress_image_features(img,s.w,s.hgt);wipe(img,size);free(img);}
        ok &= features[v] && elanpress_match_features(features[v],features[0])>=ELANPRESS_MATCH_MIN_PAIRS;
    }
    for(int v=0;v<StudyVariants;v++)studyFreeFeatures(features[v]);
    wipe(frames,StudyFrames*size*sizeof(*frames));free(frames);free(s.bg);
    printf("Capture study window processing: %s\n",ok?"pass":"fail");
    return ok?0:1;
}

static int captureStudyMain(void) {
    signal(SIGINT,interrupt);signal(SIGTERM,interrupt);cancelled=0;
    ElanpressFeatures *samples[StudyPresses][StudyVariants]={{0}};
    NSMutableData *stored=nil;
    int result=1;
    puts("采集对照：沿用已录入的指纹，共按6次，不会重新录入。按 Control+C 可停止。");
    if(!pause_prompt("请先移开手指，按回车开始。"))goto done;
    if(!open_sensor(&sensor))goto done;
    stored=loadSecret(@"fingerprints-v1",YES);
    if(!unpackPrints(stored)){puts("无法读取已录入的指纹。请允许钥匙串访问后重试。");goto done;}
    wipe(stored.mutableBytes,stored.length);stored=nil;
    printf("STUDY templates=%d threshold=%d\n",printCount,ELANPRESS_MATCH_MIN_PAIRS);
    const char *guides[]={"1/6：已录入的手指，指腹中心。","2/6：同一根手指，再按中心。",
        "3/6：同一根手指，比中心向指尖方向挪约1毫米。","4/6：同一根手指，比中心向指根方向挪约1毫米。",
        "5/6：换一根没有录入过的手指。","6/6：仍用这根没有录入过的手指。"};
    for(int p=0;p<StudyPresses&&!cancelled;p++) {
        puts(guides[p]);
        if(!pause_prompt("准备好后按回车，再等待轻放提示。") || !studyPress(p,samples[p]))goto done;
        for(int v=0;v<StudyVariants;v++) {
            if(!samples[p][v])continue;
            for(int earlier=0;earlier<p && earlier<4;earlier++) {
                if(samples[earlier][v])printf("STUDY pair=%d,%d variant=%s label=%s score=%u\n",
                    earlier+1,p+1,studyNames[v],p<4?"same":"other",
                    elanpress_match_features(samples[p][v],samples[earlier][v]));
            }
        }
    }
    if(!cancelled){result=0;puts("对照完成，已保留原有指纹。");}
done:
    if(stored)wipe(stored.mutableBytes,stored.length);
    for(int p=0;p<StudyPresses;p++)for(int v=0;v<StudyVariants;v++)studyFreeFeatures(samples[p][v]);
    clearPrints();close_sensor(&sensor);
    printf("STUDY exit=%d cancelled=%d\n",result,cancelled!=0);
    return result;
}
