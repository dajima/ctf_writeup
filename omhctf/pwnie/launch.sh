docker run -i --rm \
        -h pwnie \
        -v $(pwd):/pwnie \
        -v /glibc:/glibc \
        --workdir /pwnie \
        zhihsi/dockerpwn:2.27-1 \
        /bin/sh -c "./my_little_pwnie_bak"
