FROM python:3.13-slim
RUN apt-get update && apt-get install --no-install-recommends -y g++ libpoco-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /tests
COPY src/framework/UserAccessPolicy.h src/framework/UserAccessPolicyJSON.h /tests/framework/
COPY test_scripts/access-control/policy_test.cpp test_scripts/access-control/policy_json_test.cpp /tests/
RUN g++ -std=c++17 -Wall -Wextra -Werror -I /tests policy_test.cpp -o policy-test && \
    g++ -std=c++17 -Wall -Wextra -Werror -I /tests policy_json_test.cpp -lPocoJSON -lPocoFoundation -o policy-json-test
CMD ["sh", "-c", "./policy-test && ./policy-json-test"]
