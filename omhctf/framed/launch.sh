docker run -i --rm \
        -h babyheap \
        --name=cttt \
        -v $(pwd):/babyheap \
        -v /glibc:/glibc \
        --workdir /babyheap \
        zhihsi/dockerpwn:2.27 \
        /bin/sh -c "LD_PRELOAD=./libc.so.6 ./pwn"
