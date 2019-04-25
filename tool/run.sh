#!/bin/bash

ps -ef|grep ./tutorial|grep -v grep|awk '{print $2}'|xargs kill -9
