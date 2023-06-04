" Vim syntax file
" Language:     resynth
" Maintainer:   Gianni Tedesco <gianni@scaramanga.co.uk>
" Last Change:  Feb 24, 2016
" For bugs, patches and license go to https://github.com/resynth/resynth.vim

if version < 600
    syntax clear
elseif exists("b:current_syntax")
    finish
endif

syn keyword   resynthImport      import nextgroup=resynthModPath skipwhite skipempty
syn keyword   resynthKeyword     let nextgroup=resynthVariable skipWhite

syn match     resynthModPath     "\w\(\w\)*::[^<]"he=e-3,me=e-3
syn match     resynthModPathSep  "::"

syn match     resynthIdentifier  "\%([^[:cntrl:][:space:][:punct:][:digit:]]\|_\)\%([^[:cntrl:][:punct:][:space:]]\|_\)*" display contained
syn match     resynthFuncName    "\%([^[:cntrl:][:space:][:punct:][:digit:]]\|_\)\%([^[:cntrl:][:punct:][:space:]]\|_\)*" display contained
syn match     resynthVariable    "\%([^[:cntrl:][:space:][:punct:][:digit:]]\|_\)\%([^[:cntrl:][:punct:][:space:]]\|_\)*" display contained

syn region    resynthBoxPlacement matchgroup=resynthBoxPlacementParens start="(" end=")" contains=TOP contained
syn region    resynthBoxPlacementBalance start="(" end=")" containedin=resynthBoxPlacement transparent

syn keyword   resynthBoolean     true false

syn match     resynthFuncCall    "\w\(\w\)*("he=e-1,me=e-1

syn match     resynthOperator    display "\%(+\|-\|/\|*\|=\|\^\|&\||\|!\|>\|<\|%\)=\?"

syn match     resynthEscape      display contained "|\([0-9a-fA-F]\|\s\)*|"
syn region    resynthString      start=+"+ end=+"+ contains=resynthEscape,@Spell

syn match     resynthDecNumber   display "\<[0-9][0-9_]*"
syn match     resynthHexNumber   display "\<0x[a-fA-F0-9_]\+"

syn match     resynthShebang        /\%^#![^[].*/
syn region    resynthCommentLine    start="#"   end="$"   contains=resynthTodo,@Spell
syn region    resynthCommentLine    start="//"  end="$"   contains=resynthTodo,@Spell

syn keyword resynthTodo contained TODO FIXME XXX NB NOTE

syn match resynthSpaceError display excludenl "\s\+$"

" Default highlighting
hi def link resynthSpaceError    Error
hi def link resynthImport        Include

hi def link resynthDecNumber     resynthNumber
hi def link resynthHexNumber     resynthNumber

hi def link resynthEscape        SpecialChar
hi def link resynthString        String
hi def link resynthNumber        Number
hi def link resynthBoolean       Boolean
hi def link resynthConstant      Constant
hi def link resynthOperator      Operator
hi def link resynthKeyword       Keyword
hi def link resynthIdentifier    Identifier
hi def link resynthModPath       Include
hi def link resynthModPathSep    Delimiter
hi def link resynthFuncName      Function
hi def link resynthFuncCall      Function
hi def link resynthShebang       Comment
hi def link resynthCommentLine   Comment
hi def link resynthTodo          Todo
hi def link resynthBoxPlacementParens Delimiter

syn sync minlines=200
syn sync maxlines=500

let b:current_syntax = "resynth"
