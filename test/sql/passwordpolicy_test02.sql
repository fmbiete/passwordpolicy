DROP USER IF EXISTS test_pass;

CREATE USER test_pass WITH PASSWORD 'aaaa';

CREATE USER test_pass WITH PASSWORD 'aaaaaaaaaaaaaaa';

CREATE USER test_pass WITH PASSWORD 'aaaaaaaaaaaaaaa1234';

CREATE USER test_pass WITH PASSWORD 'aaaaaaaaaaaaaaa#*#134';

CREATE USER test_pass WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

DROP USER IF EXISTS test_pass;
