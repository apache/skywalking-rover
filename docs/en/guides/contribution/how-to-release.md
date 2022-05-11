# Apache SkyWalking Rover Release Guide

This documentation guides the release manager to release the SkyWalking Rover in the Apache Way, and also helps people to check the release for vote.

## Prerequisites

1. Close(if finished, or move to next milestone otherwise) all issues in the current milestone from [skywalking-rover](https://github.com/apache/skywalking-rover/milestones) and [skywalking](https://github.com/apache/skywalking/milestones), create a new milestone if needed.
2. Update [CHANGES.md](../../../../CHANGES.md).
3. Check the [dependency licenses](../../../../dist/LICENSE) including all dependencies.

## Add your GPG public key to Apache svn

1. Upload your GPG public key to a public GPG site, such as [MIT's site](http://pgp.mit.edu:11371/). 

1. Log in [id.apache.org](https://id.apache.org/) and submit your key fingerprint.

1. Add your GPG public key into [SkyWalking GPG KEYS](https://dist.apache.org/repos/dist/release/skywalking/KEYS) file, **you can do this only if you are a PMC member**.  You can ask a PMC member for help. **DO NOT override the existed `KEYS` file content, only append your key at the end of the file.**

## Build and sign the source code package

```shell
export VERSION=<the version to release>
git clone git@github.com:apache/skywalking-rover && cd skywalking-rover
git tag -a "v$VERSION" -m "Release Apache SkyWalking-Rover v$VERSION"
git push --tags
make release
```

**In total, six files should be automatically generated in the directory**: `apache-skywalking-rover-${VERSION}-bin.tgz`, `apache-skywalking-rover-${VERSION}-src.tgz`, and their corresponding `asc`, `sha512` files.

## Upload to Apache svn

```bash
svn co https://dist.apache.org/repos/dist/dev/skywalking/
mkdir -p skywalking/rover/"$VERSION"
cp skywalking-rover/apache-skywalking*.tgz skywalking/rover/"$VERSION"
cp skywalking-rover/apache-skywalking*.tgz.asc skywalking/rover/"$VERSION"
cp skywalking-rover/apache-skywalking-rover*.tgz.sha512 skywalking/rover/"$VERSION"

cd skywalking/rover && svn add "$VERSION" && svn commit -m "Draft Apache SkyWalking-Rover release $VERSION"
```

## Call for vote in dev@ mailing list

Call for vote in `dev@skywalking.apache.org`, **please check all links before sending the email**.

```text
Subject: [VOTE] Release Apache SkyWalking Rover version $VERSION

Content:

Hi the SkyWalking Community:
This is a call for vote to release Apache SkyWalking Rover version $VERSION.

Release notes:

 * https://github.com/apache/skywalking-rover/blob/v$VERSION/CHANGES.md

Release Candidate:

 * https://dist.apache.org/repos/dist/dev/skywalking/rover/$VERSION
 * sha512 checksums
   - sha512xxxxyyyzzz skywalking-rover-x.x.x-src.tgz
   - sha512xxxxyyyzzz skywalking-rover-x.x.x-bin.tgz

Release Tag :

 * (Git Tag) v$VERSION

Release Commit Hash :

 * https://github.com/apache/skywalking-rover/tree/<Git Commit Hash>

Keys to verify the Release Candidate :

 * https://dist.apache.org/repos/dist/release/skywalking/KEYS

Guide to build the release from source :

 * https://github.com/apache/skywalking-rover/blob/v$VERSION/docs/en/guides/contribution/how-to-release.md

Voting will start now and will remain open for at least 72 hours, all PMC members are required to give their votes.

[ ] +1 Release this package.
[ ] +0 No opinion.
[ ] -1 Do not release this package because....

Thanks.

[1] https://github.com/apache/skywalking/blob/master/docs/en/guides/How-to-release.md#vote-check
```

## Vote Check

All PMC members and committers should check these before voting +1:

1. Features test.
1. All artifacts in staging repository are published with `.asc`, `.md5`, and `sha` files.
1. Source codes and distribution packages (`skywalking-rover-$VERSION-{src,bin}.tgz`)
are in `https://dist.apache.org/repos/dist/dev/skywalking/rover/$VERSION` with `.asc`, `.sha512`.
1. `LICENSE` and `NOTICE` are in source codes and distribution package.
1. Check `shasum -c skywalking-rover-$VERSION-{src,bin}.tgz.sha512`.
1. Check `gpg --verify skywalking-rover-$VERSION-{src,bin}.tgz.asc skywalking-rover-$VERSION-{src,bin}.tgz`.
1. Build distribution from source code package by following this command, `make container-generate build`.

Vote result should follow these:

1. PMC vote is +1 binding, all others is +1 no binding.

1. Within 72 hours, you get at least 3 (+1 binding), and have more +1 than -1. Vote pass. 

1. **Send the closing vote mail to announce the result**.  When count the binding and no binding votes, please list the names of voters. An example like this:

   ```
   [RESULT][VOTE] Release Apache SkyWalking Rover version $VERSION
   
   3 days passed, we’ve got ($NUMBER) +1 bindings (and ... +1 non-bindings):
   
   (list names)
   +1 bindings:
   xxx
   ...
      
   +1 non-bindings:
   xxx
   ...
    
   Thank you for voting, I’ll continue the release process.
   ```

## Publish release

1. Move source codes tar balls and distributions to `https://dist.apache.org/repos/dist/release/skywalking/`, **you can do this only if you are a PMC member**.

    ```shell
    export SVN_EDITOR=vim
    svn mv https://dist.apache.org/repos/dist/dev/skywalking/rover/$VERSION https://dist.apache.org/repos/dist/release/skywalking/rover
    ```
    
1. Refer to the previous [PR](https://github.com/apache/skywalking-website/pull/212), update the event and download links on the website.

1. Update [Github release page](https://github.com/apache/skywalking-rover/releases), follow the previous convention.

1. Push docker image to the [Docker Hub](https://hub.docker.com/r/apache/skywalking-rover), make sure you have the write permission for push image.

   ```shell
   make docker && make docker.push
   ```

1. Send ANNOUNCE email to `dev@skywalking.apache.org` and `announce@apache.org`, the sender should use his/her Apache email account, **please check all links before sending the email**.

    ```
    Subject: [ANNOUNCEMENT] Apache SkyWalking Rover $VERSION Released

    Content:

    Hi the SkyWalking Community

    On behalf of the SkyWalking Team, I’m glad to announce that SkyWalking Rover $VERSION is now released.

    SkyWalking Rover: A lightweight collector/sidecar could be deployed closing to the target monitored system, to collect metrics, traces, and logs.

    SkyWalking: APM (application performance monitor) tool for distributed systems, especially designed for microservices, cloud native and container-based (Docker, Kubernetes, Mesos) architectures.

    Download Links: http://skywalking.apache.org/downloads/

    Release Notes : https://github.com/apache/skywalking-rover/blob/v$VERSION/CHANGES.md

    Website: http://skywalking.apache.org/

    SkyWalking Rover Resources:
    - Issue: https://github.com/apache/skywalking/issues
    - Mailing list: dev@skywalking.apache.org
    - Documents: https://github.com/apache/skywalking-rover/blob/v$VERSION/README.md
    
    The Apache SkyWalking Team
    ```

## Remove Unnecessary Releases

Please remember to remove all unnecessary releases in the mirror svn (https://dist.apache.org/repos/dist/release/skywalking/), if you don't recommend users to choose those version.
For example, you have removed the download and documentation links from the website. 
If they want old ones, the Archive repository has all of them.
