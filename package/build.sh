#/bin/sh

FULLVERSION=`grep "VERSION :" releasenote.txt | head -n1 | sed -e "s/VERSION ://" | sed -e "s/ //g"`
VERSION=`echo $FULLVERSION | sed -e "s/-.*//"`
RELEASE=`echo $FULLVERSION | sed -e "s/.*-//"`
COMPONENT=openkvi
SPEC_FILE=package/package.spec
DISTRIB=centos6
ARCH=noarch
TMP_PATH=__tmp__/$COMPONENT-$VERSION
OUTPUT=$PWD/__tmp__



rm -rf __tmp__ 
mkdir -p $TMP_PATH

install -m644 releasenote.txt $TMP_PATH/releasenote-$COMPONENT-$VERSION.txt
install -m755 ../war/openkvi.war $TMP_PATH/
install -m755 ../war/server.xml $TMP_PATH/
install -m755 ../war/favicon.ico $TMP_PATH/
install -m755 ../nodemanager/*.py $TMP_PATH/
install -m755 ../nodemanager/monitor_nodemanagerd.sh $TMP_PATH/
install -m644 ../nodemanager/etc/nodemanager.conf $TMP_PATH/
install -m644 ../nodemanager/initd/nodemanagerd $TMP_PATH/
install -m644 ./nginx_conf/* $TMP_PATH/
install -m644 ./ssl_keys/openkvi_server.key $TMP_PATH/
install -m644 ./ssl_keys/openkvi_server.crt $TMP_PATH/
install -m744 ./iptables/* $TMP_PATH/
install -m644 ./collectd.conf $TMP_PATH/
install -m644 ./index.html $TMP_PATH/



cp package.spec __tmp__/$COMPONENT.spec

cd __tmp__
tar cvzf $COMPONENT-$VERSION.tgz $COMPONENT-$VERSION
cd ..


sh rpm_builder.sh -n $COMPONENT -d $DISTRIB -a $ARCH -t $COMPONENT-$VERSION.tgz  -s $COMPONENT.spec -v $VERSION -o $OUTPUT -r $RELEASE

mkdir -p ./RPMS
mv -f $OUTPUT/*.rpm ./RPMS/
mkdir -p ./SRPMS
mv -f $OUTPUT/rpmbuild/SRPMS/*.src.rpm ./SRPMS/
rm -rf $OUTPUT
cp releasenote.txt RPMS/releasenote-$COMPONENT-$VERSION.txt
echo "Package $COMPONENT-$VERSION-$RELEASE.$DISTRIB.$ARCH.rpm is available in RPMS/"
