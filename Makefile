PLB=/usr/libexec/PlistBuddy
name=$(shell $(PLB) -c Print:name src/info.plist)
version=$(shell $(PLB) -c Print:version src/info.plist)
artifact=$(name)-$(version).alfredworkflow

all: build open

open: bin/$(artifact)
	open bin/$(artifact)

build:
	@printf '%s\n' '$(version)' | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || (printf '%s\n' 'Version must use x.x.x format'; exit 1)
	-rm bin/*.alfredworkflow
	-pushd src/alkeepass.d; GOOS=darwin GOARCH=amd64 go build -o ../ alkeepass.go; popd
	-pushd src; zip -r ../bin/$(artifact) alkeepass icon*.png *.md info.plist; popd


update: build
	cp -f src/alkeepass '/Users/mnaito/Library/Mobile Documents/com~apple~CloudDocs/Alfred/Alfred.alfredpreferences/workflows/user.workflow.8221232E-CD36-41A3-9539-B1127FE8A67A/'
	cp -f '/Users/mnaito/Library/Mobile Documents/com~apple~CloudDocs/Alfred/Alfred.alfredpreferences/workflows/user.workflow.8221232E-CD36-41A3-9539-B1127FE8A67A/info.plist' src/
