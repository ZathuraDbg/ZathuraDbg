# Contributing
This document is relevant for anyone who is interested in contributing to this project.

## Overview
The following is the list of things that you can do to contribute to this project.
- [Compile](https://github.com/ZathuraDbg/ZathuraDbg/blob/master/COMPILE.md) ZathuraDbg and work on new features or fix bugs from [issues](https://github.com/ZathuraDbg/ZathuraDbg/issues)
- [Report bugs](https://github.com/ZathuraDbg/ZathuraDbg/issues) so they can be fixed.
- Add feature requests as [issues](https://github.com/ZathuraDbg/ZathuraDbg/issues)
- [Contact Us](https://ZathuraDbg.github.io/contact)
- Send a [donation](https://ZathuraDbg.github.io/donate) to support the project
- Help us improve the [documentation](https://github.com/ZathuraDbg/ZathuraDbg)

## Getting started
- [Tutorial](https://ZathuraDbg.github.io/tutorials) of all the features of the program.
- [Architecture of ZathuraDbg](https://ZathuraDbg.github.io/architecture) (**must read**)
- Documentation of [Unicorn Engine](https://www.unicorn-engine.org/docs/), the emulation framework on which ZathuraDbg is based on.
- [ImGui](https://github.com/ocornut/imgui), the UI framework used to develop ZathuraDbg.

#### Sending a pull request

Here is a little guide on how to do a clean pull request for people who don't yet know how to use git. We recommend using [Git Extensions](https://gitextensions.github.io), but any git interface is fine.

1. First we need to [fork](https://help.github.com/articles/fork-a-repo/) the actual ZathuraDbg repo on our github account.
2. When the fork is finished, clone the repo (`git clone https://github.com/myname/ZathuraDbg.git --recurse-submodules`).
3. When pushing new features/bug/whatever to a github project the best practice is to create branches. The command `git checkout -b my-branch-name` will automatically create a branch and check it out.
4. Make all the changes you want and when finishing it, use `git add myfiles` to add it to the repo.
5. Commit your change. `git commit -m 'a message about what you changed'`. The change are applied to your local git repo.
6. Push it to your `origin`. The `origin` is your repo which is hosted on github. `git push --set-upstream origin your-branch-name`.
7. Sync with the `upstream` repo, the real ZathuraDbg repo. `git remote add upstream https://github.com/ZathuraDbg/ZathuraDbg.git`, using `git remote -v` will show which origin/upstream are setup in the local repo.
8. Sync your fork with the `upstream`, `git fetch upstream`. Now checkout your local `development` branch again `git checkout development` and merge the upstream `git merge upstream/development`.
9. Time to create the pull request! Using the GitHub UI, go to your account/repo, select the branch you already pushed, and click `Pull request`. Review your pull request and send it.
Happy PRs!

### Report bugs

If you want to have the highest chance of getting your problem solved, you are going to have to put in some effort. The vital things are:

1. Search the issue tracker to see if your bug has not been reported already.
2. Give concrete steps on how to reproduce your bug.
3. Tell us exactly which version of ZathuraDbg you used and the environment(s) you reproduced the bug in.


### Request features

Feature requests are often closed because they are out of scope. If you request one anyway, make sure to give a clear description of the desired behaviour and give clear examples of cases where your feature would be useful.

We understand that it can be disappointing to not get your feature implemented, but opening an issue is the best way to communicate it regardless.

### Contact Us
You can contact us through the following channels:
- [ZathuraDbg](https://x.com/ZathuraDbg) on X/Twitter
- [Mail us](mailto:crretsim@gmail.com)
- Join our [discord](https://discord.com/invite/dyMuwaZfPf)
