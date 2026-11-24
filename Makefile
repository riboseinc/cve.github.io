SHELL := /bin/bash

all: _site

clean:
	rm -rf _site _concepts feeds

feeds: | bundle
	bundle exec ruby scripts/generate_feeds.rb
	bundle exec ruby scripts/validate_feeds.rb

validate-feeds: | bundle
	bundle exec ruby scripts/validate_feeds.rb

test: feeds
	bundle exec ruby test/test_feeds.rb

_site: feeds | bundle
	bundle exec jekyll build

bundle:
	bundle

serve: feeds
	bundle exec jekyll serve

update-init:
	git submodule update --init

update-modules:
	git submodule foreach git pull origin master

.PHONY: bundle all open serve clean feeds validate-feeds test update-init update-modules
