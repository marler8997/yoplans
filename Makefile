CC=gcc -std=c99 -I../weblib
SQL_FLAGS=-I/usr/include/mysql -DBIG_JOINS=1 -fno-strict-aliasing -DUNIV_LINUX -DUNIV_LINUX -rdynamic -L/usr/lib/mysql -lmysqlclient

WEBLIB=../weblib
WEBLIB_OBJ=${WEBLIB}/build/obj

PAGES=www/index www/login www/register

all: pages 
pages: ${PAGES}

deploy: all
	cp -r www/* /var/www/yp



www/index: index.c sql.o print.o ${WEBLIB_OBJ}/sha1.o ${WEBLIB_OBJ}/string_util.o password.o send.o ${WEBLIB_OBJ}/base64.o
	${CC} ${SQL_FLAGS} -o www/index index.c print.o sql.o ${WEBLIB_OBJ}/sha1.o ${WEBLIB_OBJ}/string_util.o password.o send.o ${WEBLIB_OBJ}/base64.o

www/login: login.c ${WEBLIB_OBJ}/request.o sql.o print.o ${WEBLIB_OBJ}/sha1.o ${WEBLIB_OBJ}/url.o ${WEBLIB_OBJ}/string_util.o password.o ${WEBLIB_OBJ}/sid.o send.o ${WEBLIB_OBJ}/base64.o
	${CC} ${SQL_FLAGS} -o www/login login.c print.o ${WEBLIB_OBJ}/request.o sql.o ${WEBLIB_OBJ}/sha1.o ${WEBLIB_OBJ}/url.o ${WEBLIB_OBJ}/string_util.o password.o ${WEBLIB_OBJ}/sid.o send.o ${WEBLIB_OBJ}/base64.o

www/register: register.c ${WEBLIB_OBJ}/request.o sql.o print.o ${WEBLIB_OBJ}/sha1.o ${WEBLIB_OBJ}/url.o ${WEBLIB_OBJ}/string_util.o password.o send.o
	${CC} ${SQL_FLAGS} -o www/register register.c print.o ${WEBLIB_OBJ}/request.o sql.o ${WEBLIB_OBJ}/sha1.o ${WEBLIB_OBJ}/url.o ${WEBLIB_OBJ}/string_util.o password.o send.o

#
# libraries
#
print.o: print.c print.h
	${CC} -c print.c

send.o: send.c send.h ${WEBLIB_OBJ}/string_util.o
	${CC} -c send.c

sql.o: sql.c
	${CC} ${SQL_FLAGS} -c sql.c

password.o: password.c
	${CC} -c password.c

#
# clean
#
clean:
	rm -f *.o *~ www/*~ debug/*~ ${PAGES}