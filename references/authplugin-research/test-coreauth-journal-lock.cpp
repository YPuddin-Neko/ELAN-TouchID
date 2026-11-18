#include "native-coreauth-journal-lock.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <sys/wait.h>
int main(){
 char root[]="/tmp/elan-journal-lock-test-XXXXXX";assert(mkdtemp(root));
 char lockPath[256],journal[256],alias[256];snprintf(lockPath,sizeof(lockPath),"%s/lock",root);snprintf(journal,sizeof(journal),"%s/state",root);snprintf(alias,sizeof(alias),"%s/alias",root);
 ino_t inode=0;
 {
  CoreAuthJournalLock a(lockPath,geteuid());assert(a.held());struct stat st{};assert(!stat(lockPath,&st));inode=st.st_ino;
  CoreAuthJournalLock b(lockPath,geteuid());assert(!b.held()&&(b.error()==EWOULDBLOCK||b.error()==EAGAIN));
  // A second cooperating cleanup/creator cannot enter A's final-read/unlink gap.
  int fd=open(journal,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);close(fd);
  bool created=false;{CoreAuthJournalLock creator(lockPath,geteuid());if(creator.held())created=true;}
  assert(!created&&access(journal,F_OK)==0);assert(!unlink(journal));
  pid_t child=fork();assert(child>=0);if(!child){CoreAuthJournalLock c(lockPath,geteuid());_exit(c.held()?1:0);}
  int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 }
 {CoreAuthJournalLock c(lockPath,geteuid());assert(c.held());struct stat st{};assert(!stat(lockPath,&st)&&st.st_ino==inode);}
 assert(!chmod(lockPath,0644));{CoreAuthJournalLock bad(lockPath,geteuid());assert(!bad.held());}assert(!chmod(lockPath,0600));
 {CoreAuthJournalLock bad(lockPath,geteuid()+1);assert(!bad.held());}
 assert(!link(lockPath,alias));{CoreAuthJournalLock bad(lockPath,geteuid());assert(!bad.held());}assert(!unlink(alias));
 assert(!symlink(lockPath,alias));{CoreAuthJournalLock bad(alias,geteuid());assert(!bad.held());}assert(!unlink(alias));
 assert(!mkfifo(alias,0600));{CoreAuthJournalLock bad(alias,geteuid());assert(!bad.held());}assert(!unlink(alias));
 assert(!unlink(lockPath));assert(!rmdir(root));puts("cooperative journal lock: contention, creator exclusion, persistent inode, metadata and nonregular rejection passed");
}
