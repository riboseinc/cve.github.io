SHELL := /bin/bash

all: _site

clean:
	rm -rf _site feeds

feeds: | bundle
	bundle exec ruby scripts/generate_feeds.rb
	bundle exec ruby scripts/validate_feeds.rb

validate-feeds: | bundle
	bundle exec ruby scripts/validate_feeds.rb

test: feeds
	bundle exec ruby test/test_feeds.rb

_site: feeds
	rm -rf _site
	mkdir -p _site
	cp index.html _site/index.html
	cp -R feeds _site/feeds

bundle:
	bundle install

.PHONY: bundle all clean feeds validate-feeds test _site
