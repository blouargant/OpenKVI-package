#/bin/sh

function help()
{
echo ""
echo "to build the RPM file ..."
echo "Usage: ncxRpmBuilder [OPTION] ..."
echo "Options:"
echo " -v, --version    : set rpm version"
echo " -n, --name       : set rpm name"
echo " -v, --version    : set rpm version"
echo " -r, --release    : set rpm release number"
echo " -d, --distrib    : set distribution"
echo "                    default is host's distribution"
echo " -a, --arch       : set architecture"
echo "                    default is host's architecture"
echo " -t, --tar        : set source tar location"
echo " -s, --spec       : set RPM's spec file"
echo " -o, --out        : set output directory location"
echo ""
}

function GetOpts()
{
NAME=?
DISTRIB=?
VERSION=0
RELEASE=0
ARCH=`uname -p`

## Gets command line options & args ##
TEMP=`getopt -o hv:r:a:d:n:t:s:o: -l help,version:,release:,arch:,distrib:,name:,tar:,spec:,out: -n "rpm_builder.sh" -- "$@"`
if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi
eval set -- "$TEMP"
while true ; do
	case "$1" in
		-h|--help) help; exit 0;;
		-n|--name) NAME=$2; shift 2 ;;
		-v|--version) VERSION=$2; shift 2 ;;
		-r|--release) RELEASE=$2; shift 2 ;;
		-d|--distrib) DISTRIB=$2; shift 2 ;;
		-a|--arch) ARCH=$2; shift 2 ;;
		-t|--tar) SOURCE=$2; shift 2 ;;
		-s|--spec) SPEC=$2; shift 2 ;;
		-o|--out) OUTDIR=$2; shift 2 ;;
		--) shift ; break;;
		*) echo "Internal error; wrong option :$1"; exit 1;;
	esac
done
## end ##
}

function CreateRpmEnv()
{
mkdir -p $OUTDIR/rpmbuild/SOURCES
mkdir -p $OUTDIR/rpmbuild/BUILD
mkdir -p $OUTDIR/rpmbuild/RPMS/$ARCH
mkdir -p $OUTDIR/rpmbuild/SPECS
mkdir -p $OUTDIR/rpmbuild/SRPMS
mkdir -p $OUTDIR/tmp

cp -f ~/.rpmmacros ~/.rpmmacros.backup
echo "%_topdir $OUTDIR/rpmbuild" > ~/.rpmmacros
echo "%_tmppath $OUTDIR/tmp" >> ~/.rpmmacros
mv $OUTDIR/$SOURCE $OUTDIR/rpmbuild/SOURCES/
mv $OUTDIR/$SPEC $OUTDIR/rpmbuild/SPECS/
}

function BuildRPM()
{

cd $OUTDIR/rpmbuild/SPECS

perl -p -i -e "s/^Name:.*/Name: $NAME/" $SPEC
perl -p -i -e "s/^Version:.*/Version: $VERSION/" $SPEC
perl -p -i -e "s/^Release:.*/Release: $RELEASE.$DISTRIB/" $SPEC
perl -p -i -e "s/^Distribution:.*/Distribution: $DISTRIB/" $SPEC
perl -p -i -e "s/^BuildArch:.*/BuildArch: $ARCH/" $SPEC
perl -p -i -e "s/^Source0:.*/Source0: $SOURCE/" $SPEC

echo NAME=$NAME
echo VERSION=$VERSION
echo RELEASE=$RELEASE
echo DISTRIB=$DISTRIB
echo ARCH=$ARCH
echo SPEC=$SPEC

rpmbuild -ba $SPEC
mv $OUTDIR/rpmbuild/RPMS/$ARCH/$NAME-$VERSION-$RELEASE.$DISTRIB.$ARCH.rpm $OUTDIR/
}


GetOpts $@
CreateRpmEnv
BuildRPM
cp -f ~/.rpmmacros.backup ~/.rpmmacros
