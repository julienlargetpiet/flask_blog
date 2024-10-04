#!/bin/bash

for i in $(ls *.html)
do
        sed s/"<!DOCTYPE>"/"<!DOCTYPE html>"/g -i $i
done
