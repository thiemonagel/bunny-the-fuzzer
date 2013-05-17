#ifndef _HAVE_UTIL_H
#define _HAVE_UTIL_H

/* Don't rely on the OS to service a read() call in one go. */
static inline ssize_t sure_read(_s32 fd, void* buf, size_t len) {
  ssize_t total = 0;

  do {
    ssize_t cur = read(fd,buf,len);
    if (cur <= 0) return cur;
    total += cur;
    len   -= cur;
    buf   += cur;
  } while (len);

  return total;
  
}


/* Don't rely on the OS to service a write() call in one go. */
static inline ssize_t sure_write(_s32 fd, void* buf, size_t len) {
  ssize_t total = 0;

  do {
    ssize_t cur = write(fd,buf,len);
    if (cur < 0) return cur;
    total += cur;
    len   -= cur;
    buf   += cur;
  } while (len);

  return total;
  
}

#endif /* ! _HAVE_UTIL_H */
