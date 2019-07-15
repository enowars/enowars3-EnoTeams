#!/bin/sh

currenttime=$(date +%m_%d_%H_%M)
ssh eno@enowars.com pg_dump postgresql://postgres:password@localhost:5432/postgres -f dump.sql
scp eno@enowars.com:dump.sql ~/dumps/"$currenttime"_dump.sql
ssh eno@enowars.com rm dump.sql