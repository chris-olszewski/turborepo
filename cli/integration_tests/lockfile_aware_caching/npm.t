Setup
  $ . ${TESTDIR}/../setup.sh
  $ . ${TESTDIR}/setup.sh $(pwd) npm

Populate cache
  $ ${TURBO} build --filter=a
  \xe2\x80\xa2 Packages in scope: a (esc)
  \xe2\x80\xa2 Running build in 1 packages (esc)
  \xe2\x80\xa2 Remote caching disabled (esc)
  a:build: cache miss, executing 17b0e61e4e2d05ff
  a:build: 
  a:build: > build
  a:build: > echo 'building'
  a:build: 
  a:build: building
  
   Tasks:    1 successful, 1 total
  Cached:    0 cached, 1 total
    Time:\s*[\.0-9]+m?s  (re)
  
  $ ${TURBO} build --filter=b
  \xe2\x80\xa2 Packages in scope: b (esc)
  \xe2\x80\xa2 Running build in 1 packages (esc)
  \xe2\x80\xa2 Remote caching disabled (esc)
  b:build: cache miss, executing 1a65f0cb3dc93890
  b:build: 
  b:build: > build
  b:build: > echo 'building'
  b:build: 
  b:build: building
  
   Tasks:    1 successful, 1 total
  Cached:    0 cached, 1 total
    Time:\s*[\.0-9]+m?s  (re)
  

Bump dependency for b and rebuild
Both a and b should have a cache miss since npm isn't implemented
  $ patch package-lock.json package-lock.patch
  patching file package-lock.json
  $ ${TURBO} build  --filter=a
  \xe2\x80\xa2 Packages in scope: a (esc)
  \xe2\x80\xa2 Running build in 1 packages (esc)
  \xe2\x80\xa2 Remote caching disabled (esc)
  a:build: cache miss, executing f3caf2df1844f930
  a:build: 
  a:build: > build
  a:build: > echo 'building'
  a:build: 
  a:build: building
  
   Tasks:    1 successful, 1 total
  Cached:    0 cached, 1 total
    Time:\s*[\.0-9]+m?s  (re)
  

  $ ${TURBO} build  --filter=b
  \xe2\x80\xa2 Packages in scope: b (esc)
  \xe2\x80\xa2 Running build in 1 packages (esc)
  \xe2\x80\xa2 Remote caching disabled (esc)
  b:build: cache miss, executing f5eb13a5f2db7015
  b:build: 
  b:build: > build
  b:build: > echo 'building'
  b:build: 
  b:build: building
  
   Tasks:    1 successful, 1 total
  Cached:    0 cached, 1 total
    Time:\s*[\.0-9]+m?s  (re)
  
 
Bump of root workspace invalidates all packages
  $ patch package-lock.json turbo-bump.patch
  patching file package-lock.json
  $ ${TURBO} build  --filter=a
  \xe2\x80\xa2 Packages in scope: a (esc)
  \xe2\x80\xa2 Running build in 1 packages (esc)
  \xe2\x80\xa2 Remote caching disabled (esc)
  a:build: cache miss, executing 57198bf230b5a962
  a:build: 
  a:build: > build
  a:build: > echo 'building'
  a:build: 
  a:build: building
  
   Tasks:    1 successful, 1 total
  Cached:    0 cached, 1 total
    Time:\s*[\.0-9]+m?s  (re)
  
  $ ${TURBO} build  --filter=b
  \xe2\x80\xa2 Packages in scope: b (esc)
  \xe2\x80\xa2 Running build in 1 packages (esc)
  \xe2\x80\xa2 Remote caching disabled (esc)
  b:build: cache miss, executing 538d5cb242612f64
  b:build: 
  b:build: > build
  b:build: > echo 'building'
  b:build: 
  b:build: building
  
   Tasks:    1 successful, 1 total
  Cached:    0 cached, 1 total
    Time:\s*[\.0-9]+m?s  (re)
  
