PORTNAME=	keyrad
DISTVERSION=	2.0.3
CATEGORIES=	security

MAINTAINER=	marco.moenig@sec73.io
COMMENT=	Keycloak RADIUS authentication server
WWW=		https://github.com/gpappsoft/keyrad

LICENSE=	APACHE20
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		go:modules
USE_GITHUB=	yes
GH_ACCOUNT=	gpappsoft

# Go module dependencies are vendored in the source tree (vendor/), so the
# build runs fully offline as required by poudriere/OPNsense build jails.
# No GH_TUPLE / network access is needed at build time.
GO_BUILDFLAGS=	-mod=vendor
GO_TARGET=	.:keyrad

PLIST_FILES=	bin/keyrad

.include <bsd.port.mk>
