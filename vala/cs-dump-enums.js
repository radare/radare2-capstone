#!/usr/bin/env node

const fs = require ("fs");
const progname="cs-dump-enums.js";
const argv = process.argv.slice (2);

(function (av) {
 var arch = av[0];
 if (!arch) {
   return console.log (
     "Usage: node "+progname+" [x86|arm|arm64|ppc|mips] [enum-name]");
 }
 const paths = [
   arch,
   'include/'+arch+'.h',
   'capstone/include/'+arch+'.h',
   '/usr/include/capstone/'+arch+'.h'
 ];
 paths.forEach (
   function (file) {
     if (fs.existsSync (file)) {
       console.error (" API_VERSION = "+getApiVersion (file));
       console.error (" CAPSTONE_PATH = "+file);
       parseEnumsFromFile (file, av[1]);
       process.exit (0);
     }
     return;

     function getApiVersion(filename) {
       var apifile = file.split ('/').slice (0, -1).join('/')+'/capstone.h';
       if (fs.existsSync (apifile)) {
         var str = ''+fs.readFileSync (apifile);
         var lines = str.split(/\n/g);
         for (var i = 0; i<lines.length; i++) {
           var line = lines[i].trim ();
           if (line.match(/CS_API_MAJOR/)) {
             major = line.split (/ /)[2];
           } else
           if (line.match(/CS_API_MINOR/)) {
             minor = line.split (/ /)[2];
             return major+'.'+minor;
           }
         }
       }
     }
     function parseEnumsFromFile (filename, group) {
       try { var str = ''+fs.readFileSync (filename); } catch (e) { return; }
       var lines = str.split (/\n/);
       var args = lines.map (function (x) {
         return x.replace(/\/\*.*\*\//,'').replace(/\/\/.*/,'');
       });
       var words = args.map (function (x) {
         return x.replace ('=',' = ').split (/[ \n();]/);
       }).join ().split (',').map (function (x) { return x.trim (); });
       var idx = 0;
       var key = '';
       var name = '';
       var mute = false;
       var n_enum = 0;
       const nextWord = 'do { x = words[++i].trim(); if (i>=words.length) return; } while (!x);';
       const printEnum = 'if (!group || name===group) '+
       'console.log (group?"\t\t"+okey.split("_").slice(2).join("_")+" = "+idx+",":name+" "+okey+" "+idx);isNaN(idx)||idx++';
       for (var i=0; i<words.length; i++) {
         var x = words[i];
         if (!x) continue;
         if (x=='/*') mute = true;
             else if (x=='*/') mute = false;
         if (mute) continue;
         if (x=="enum") {
           eval (nextWord);
           if (x === '{') {
             name = 'unnamed_'+n_enum++;
           } else {
             name = x;
             eval (nextWord);
           }
           if (!group)
             console.log ("// "+name);
           if (x != '{')
             return;
           eval (nextWord);
           var expect_eq_value = false;
           var key = undefined;
           var okey = undefined;
           while (true) {
             mute = (x==='/*')? true: (x==='*/')? false: mute
             if (mute) {
               eval (nextWord);
               continue;
             }
             if (x === '}') {
               okey = key;
               eval (printEnum);
               // TODO restore okey wat
               break;
             }
             if (expect_eq_value) {
               expect_eq_value = false;
               idx = x;
             } else if (x===',') {
               console.log (name+" "+okey+" "+idx++);
               eval (printEnum);
             } else if (x==='=') {
               expect_eq_value = true;
             } else {
               if ((okey=key))
                 eval (printEnum);
               key = x;
             }
             eval (nextWord);
           }
         }
       }
     }
   });
})(argv);
