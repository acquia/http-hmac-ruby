#!/usr/bin/env rackup -p8010

require "bundler/setup"
Bundler.require

require_relative 'app'

run Example::App
