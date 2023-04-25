# Contributing to this library
We want to make contributing to this project as easy and transparent as
possible.

## Pull Requests
We actively welcome your pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. If you haven't already, complete the Contributor License Agreement ("CLA").

### Special note regarding MySQL based tests
We support MySQL directly within this repository. In order to utilize a MySQL database you may utilize the supplied [```docker-compose.yml```](docker-compose.yml) specification. It will create a basic database (named ```default```) and configure a container with the appropriate ports opened and mapped to the MySQL port. A valid [docker](https://www.docker.com/products/docker-desktop) instance is a dependency for this tool.

You can instantiate the container with
```bash
cd <root of repository>

docker compose up [-d]
```
where the ```-d``` flag indicates to background the process. If you want to run the container interactively, don't add this flag.

When finished you can terminate the container you can terminate it with ```CTRL-C``` if you ran it interactively and ```docker compose down``` if you ran it with the ```-d``` flag.

The MySQL connection info for this test container is
```
MySQL port opened on local machine: 8001
User: "root"
Password: "example"
Default database: "default"
```

You can see an example configured connection in the code [here](akd_mysql/src/mysql_db_tests.rs), line 29.

## Contributor License Agreement ("CLA")
In order to accept your pull request, we need you to submit a CLA. You only need
to do this once to work on any of Facebook's open source projects.

Complete your CLA here: <https://code.facebook.com/cla>

## Issues
We use GitHub issues to track public bugs. Please ensure your description is
clear and has sufficient instructions to be able to reproduce the issue.

Facebook has a [bounty program](https://www.facebook.com/whitehat/) for the safe
disclosure of security bugs. In those cases, please go through the process
outlined on that page and do not file a public issue.

## License

By contributing to akd, you agree that your contributions will be
licensed under both the LICENSE-MIT and LICENSE-APACHE files in the root
directory of this source tree.