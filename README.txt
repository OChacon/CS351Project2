Starbuck Beagley & Oscar Chacon
CSCI-351
Project 2: 351dns README

Our high-level approach was to separate functionality between query generation, response parsing and error checking. We ended up creating several functions for translating between strings, binary, decimal and hexadecimal as well. We chose Python for its socket library and vast online resources.

The biggest challenge of this project was keeping track of indices, as being off by a single index corrupted all future interpretation and could be difficult to track down. Also, some servers do not repeat duplicate portions of their domain name responses. This should be referred to in the "name" portion of the answer section of their responses, but it is not. For example, Google's mail servers all have "aspmx.l" as part of their domains, but it only shows up in the first of five responses with an mx query.

We were thorough in our attempt to meet all project requirements. As for the code itself, we believe it is efficient, well-documented and contains minimal repetition. We made our best effort to check for bad responses, although we are not certain we've accounted for every conceivable corruption.

We tested our code purely by console output. We did so frequently to easily identify and correct problems caused by recent changes.