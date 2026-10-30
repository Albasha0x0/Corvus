namespace Corvus.Native.Pe;

/// <summary>Names of the ordinal imports of three system libraries, as the import hash resolves them.</summary>
internal static class ImportOrdinals
{
    // Source: the ordlookup tables of pefile 2023.2.7, names lower-cased; wsock32 uses the ws2_32 table there.
    private static readonly Dictionary<string, string> Tables = new(StringComparer.Ordinal)
    {
        ["ws2_32.dll"] =
            "1:accept,2:bind,3:closesocket,4:connect,5:getpeername,6:getsockname,7:getsockopt,8:htonl," +
            "9:htons,10:ioctlsocket,11:inet_addr,12:inet_ntoa,13:listen,14:ntohl,15:ntohs,16:recv," +
            "17:recvfrom,18:select,19:send,20:sendto,21:setsockopt,22:shutdown,23:socket,24:getaddrinfow," +
            "25:getnameinfow,26:wsapsetpostroutine,27:freeaddrinfow,28:wpucompleteoverlappedrequest," +
            "29:wsaaccept,30:wsaaddresstostringa,31:wsaaddresstostringw,32:wsacloseevent,33:wsaconnect," +
            "34:wsacreateevent,35:wsaduplicatesocketa,36:wsaduplicatesocketw,37:wsaenumnamespaceprovidersa," +
            "38:wsaenumnamespaceprovidersw,39:wsaenumnetworkevents,40:wsaenumprotocolsa,41:wsaenumprotocolsw," +
            "42:wsaeventselect,43:wsagetoverlappedresult,44:wsagetqosbyname,45:wsagetserviceclassinfoa," +
            "46:wsagetserviceclassinfow,47:wsagetserviceclassnamebyclassida," +
            "48:wsagetserviceclassnamebyclassidw,49:wsahtonl,50:wsahtons,51:gethostbyaddr,52:gethostbyname," +
            "53:getprotobyname,54:getprotobynumber,55:getservbyname,56:getservbyport,57:gethostname," +
            "58:wsainstallserviceclassa,59:wsainstallserviceclassw,60:wsaioctl,61:wsajoinleaf," +
            "62:wsalookupservicebegina,63:wsalookupservicebeginw,64:wsalookupserviceend," +
            "65:wsalookupservicenexta,66:wsalookupservicenextw,67:wsanspioctl,68:wsantohl,69:wsantohs," +
            "70:wsaproviderconfigchange,71:wsarecv,72:wsarecvdisconnect,73:wsarecvfrom," +
            "74:wsaremoveserviceclass,75:wsaresetevent,76:wsasend,77:wsasenddisconnect,78:wsasendto," +
            "79:wsasetevent,80:wsasetservicea,81:wsasetservicew,82:wsasocketa,83:wsasocketw," +
            "84:wsastringtoaddressa,85:wsastringtoaddressw,86:wsawaitformultipleevents," +
            "87:wscdeinstallprovider,88:wscenablensprovider,89:wscenumprotocols,90:wscgetproviderpath," +
            "91:wscinstallnamespace,92:wscinstallprovider,93:wscuninstallnamespace,94:wscupdateprovider," +
            "95:wscwritenamespaceorder,96:wscwriteproviderorder,97:freeaddrinfo,98:getaddrinfo," +
            "99:getnameinfo,101:wsaasyncselect,102:wsaasyncgethostbyaddr,103:wsaasyncgethostbyname," +
            "104:wsaasyncgetprotobynumber,105:wsaasyncgetprotobyname,106:wsaasyncgetservbyport," +
            "107:wsaasyncgetservbyname,108:wsacancelasyncrequest,109:wsasetblockinghook," +
            "110:wsaunhookblockinghook,111:wsagetlasterror,112:wsasetlasterror,113:wsacancelblockingcall," +
            "114:wsaisblocking,115:wsastartup,116:wsacleanup,151:__wsafdisset,500:wep",
        ["oleaut32.dll"] =
            "2:sysallocstring,3:sysreallocstring,4:sysallocstringlen,5:sysreallocstringlen,6:sysfreestring," +
            "7:sysstringlen,8:variantinit,9:variantclear,10:variantcopy,11:variantcopyind," +
            "12:variantchangetype,13:varianttimetodosdatetime,14:dosdatetimetovarianttime,15:safearraycreate," +
            "16:safearraydestroy,17:safearraygetdim,18:safearraygetelemsize,19:safearraygetubound," +
            "20:safearraygetlbound,21:safearraylock,22:safearrayunlock,23:safearrayaccessdata," +
            "24:safearrayunaccessdata,25:safearraygetelement,26:safearrayputelement,27:safearraycopy," +
            "28:dispgetparam,29:dispgetidsofnames,30:dispinvoke,31:createdisptypeinfo,32:createstddispatch," +
            "33:registeractiveobject,34:revokeactiveobject,35:getactiveobject,36:safearrayallocdescriptor," +
            "37:safearrayallocdata,38:safearraydestroydescriptor,39:safearraydestroydata,40:safearrayredim," +
            "41:safearrayallocdescriptorex,42:safearraycreateex,43:safearraycreatevectorex," +
            "44:safearraysetrecordinfo,45:safearraygetrecordinfo,46:varparsenumfromstr,47:varnumfromparsenum," +
            "48:vari2fromui1,49:vari2fromi4,50:vari2fromr4,51:vari2fromr8,52:vari2fromcy,53:vari2fromdate," +
            "54:vari2fromstr,55:vari2fromdisp,56:vari2frombool,57:safearraysetiid,58:vari4fromui1," +
            "59:vari4fromi2,60:vari4fromr4,61:vari4fromr8,62:vari4fromcy,63:vari4fromdate,64:vari4fromstr," +
            "65:vari4fromdisp,66:vari4frombool,67:safearraygetiid,68:varr4fromui1,69:varr4fromi2," +
            "70:varr4fromi4,71:varr4fromr8,72:varr4fromcy,73:varr4fromdate,74:varr4fromstr,75:varr4fromdisp," +
            "76:varr4frombool,77:safearraygetvartype,78:varr8fromui1,79:varr8fromi2,80:varr8fromi4," +
            "81:varr8fromr4,82:varr8fromcy,83:varr8fromdate,84:varr8fromstr,85:varr8fromdisp," +
            "86:varr8frombool,87:varformat,88:vardatefromui1,89:vardatefromi2,90:vardatefromi4," +
            "91:vardatefromr4,92:vardatefromr8,93:vardatefromcy,94:vardatefromstr,95:vardatefromdisp," +
            "96:vardatefrombool,97:varformatdatetime,98:varcyfromui1,99:varcyfromi2,100:varcyfromi4," +
            "101:varcyfromr4,102:varcyfromr8,103:varcyfromdate,104:varcyfromstr,105:varcyfromdisp," +
            "106:varcyfrombool,107:varformatnumber,108:varbstrfromui1,109:varbstrfromi2,110:varbstrfromi4," +
            "111:varbstrfromr4,112:varbstrfromr8,113:varbstrfromcy,114:varbstrfromdate,115:varbstrfromdisp," +
            "116:varbstrfrombool,117:varformatpercent,118:varboolfromui1,119:varboolfromi2,120:varboolfromi4," +
            "121:varboolfromr4,122:varboolfromr8,123:varboolfromdate,124:varboolfromcy,125:varboolfromstr," +
            "126:varboolfromdisp,127:varformatcurrency,128:varweekdayname,129:varmonthname,130:varui1fromi2," +
            "131:varui1fromi4,132:varui1fromr4,133:varui1fromr8,134:varui1fromcy,135:varui1fromdate," +
            "136:varui1fromstr,137:varui1fromdisp,138:varui1frombool,139:varformatfromtokens," +
            "140:vartokenizeformatstring,141:varadd,142:varand,143:vardiv,144:dllcanunloadnow," +
            "145:dllgetclassobject,146:dispcallfunc,147:variantchangetypeex,148:safearrayptrofindex," +
            "149:sysstringbytelen,150:sysallocstringbytelen,151:dllregisterserver,152:vareqv,153:varidiv," +
            "154:varimp,155:varmod,156:varmul,157:varor,158:varpow,159:varsub,160:createtypelib," +
            "161:loadtypelib,162:loadregtypelib,163:registertypelib,164:querypathofregtypelib," +
            "165:lhashvalofnamesys,166:lhashvalofnamesysa,167:varxor,168:varabs,169:varfix," +
            "170:oabuildversion,171:clearcustdata,172:varint,173:varneg,174:varnot,175:varround,176:varcmp," +
            "177:vardecadd,178:vardecdiv,179:vardecmul,180:createtypelib2,181:vardecsub,182:vardecabs," +
            "183:loadtypelibex,184:systemtimetovarianttime,185:varianttimetosystemtime,186:unregistertypelib," +
            "187:vardecfix,188:vardecint,189:vardecneg,190:vardecfromui1,191:vardecfromi2,192:vardecfromi4," +
            "193:vardecfromr4,194:vardecfromr8,195:vardecfromdate,196:vardecfromcy,197:vardecfromstr," +
            "198:vardecfromdisp,199:vardecfrombool,200:geterrorinfo,201:seterrorinfo,202:createerrorinfo," +
            "203:vardecround,204:vardeccmp,205:vari2fromi1,206:vari2fromui2,207:vari2fromui4," +
            "208:vari2fromdec,209:vari4fromi1,210:vari4fromui2,211:vari4fromui4,212:vari4fromdec," +
            "213:varr4fromi1,214:varr4fromui2,215:varr4fromui4,216:varr4fromdec,217:varr8fromi1," +
            "218:varr8fromui2,219:varr8fromui4,220:varr8fromdec,221:vardatefromi1,222:vardatefromui2," +
            "223:vardatefromui4,224:vardatefromdec,225:varcyfromi1,226:varcyfromui2,227:varcyfromui4," +
            "228:varcyfromdec,229:varbstrfromi1,230:varbstrfromui2,231:varbstrfromui4,232:varbstrfromdec," +
            "233:varboolfromi1,234:varboolfromui2,235:varboolfromui4,236:varboolfromdec,237:varui1fromi1," +
            "238:varui1fromui2,239:varui1fromui4,240:varui1fromdec,241:vardecfromi1,242:vardecfromui2," +
            "243:vardecfromui4,244:vari1fromui1,245:vari1fromi2,246:vari1fromi4,247:vari1fromr4," +
            "248:vari1fromr8,249:vari1fromdate,250:vari1fromcy,251:vari1fromstr,252:vari1fromdisp," +
            "253:vari1frombool,254:vari1fromui2,255:vari1fromui4,256:vari1fromdec,257:varui2fromui1," +
            "258:varui2fromi2,259:varui2fromi4,260:varui2fromr4,261:varui2fromr8,262:varui2fromdate," +
            "263:varui2fromcy,264:varui2fromstr,265:varui2fromdisp,266:varui2frombool,267:varui2fromi1," +
            "268:varui2fromui4,269:varui2fromdec,270:varui4fromui1,271:varui4fromi2,272:varui4fromi4," +
            "273:varui4fromr4,274:varui4fromr8,275:varui4fromdate,276:varui4fromcy,277:varui4fromstr," +
            "278:varui4fromdisp,279:varui4frombool,280:varui4fromi1,281:varui4fromui2,282:varui4fromdec," +
            "283:bstr_usersize,284:bstr_usermarshal,285:bstr_userunmarshal,286:bstr_userfree," +
            "287:variant_usersize,288:variant_usermarshal,289:variant_userunmarshal,290:variant_userfree," +
            "291:lpsafearray_usersize,292:lpsafearray_usermarshal,293:lpsafearray_userunmarshal," +
            "294:lpsafearray_userfree,295:lpsafearray_size,296:lpsafearray_marshal,297:lpsafearray_unmarshal," +
            "298:vardeccmpr8,299:varcyadd,300:dllunregisterserver,301:oacreatetypelib2,303:varcymul," +
            "304:varcymuli4,305:varcysub,306:varcyabs,307:varcyfix,308:varcyint,309:varcyneg,310:varcyround," +
            "311:varcycmp,312:varcycmpr8,313:varbstrcat,314:varbstrcmp,315:varr8pow,316:varr4cmpr8," +
            "317:varr8round,318:varcat,319:vardatefromudateex,322:getrecordinfofromguids," +
            "323:getrecordinfofromtypeinfo,325:setvarconversionlocalesetting," +
            "326:getvarconversionlocalesetting,327:setoanocache,329:varcymuli8,330:vardatefromudate," +
            "331:varudatefromdate,332:getaltmonthnames,333:vari8fromui1,334:vari8fromi2,335:vari8fromr4," +
            "336:vari8fromr8,337:vari8fromcy,338:vari8fromdate,339:vari8fromstr,340:vari8fromdisp," +
            "341:vari8frombool,342:vari8fromi1,343:vari8fromui2,344:vari8fromui4,345:vari8fromdec," +
            "346:vari2fromi8,347:vari2fromui8,348:vari4fromi8,349:vari4fromui8,360:varr4fromi8," +
            "361:varr4fromui8,362:varr8fromi8,363:varr8fromui8,364:vardatefromi8,365:vardatefromui8," +
            "366:varcyfromi8,367:varcyfromui8,368:varbstrfromi8,369:varbstrfromui8,370:varboolfromi8," +
            "371:varboolfromui8,372:varui1fromi8,373:varui1fromui8,374:vardecfromi8,375:vardecfromui8," +
            "376:vari1fromi8,377:vari1fromui8,378:varui2fromi8,379:varui2fromui8,401:oleloadpictureex," +
            "402:oleloadpicturefileex,411:safearraycreatevector,412:safearraycopydata,413:vectorfrombstr," +
            "414:bstrfromvector,415:oleicontocursor,416:olecreatepropertyframeindirect," +
            "417:olecreatepropertyframe,418:oleloadpicture,419:olecreatepictureindirect," +
            "420:olecreatefontindirect,421:oletranslatecolor,422:oleloadpicturefile,423:olesavepicturefile," +
            "424:oleloadpicturepath,425:varui4fromi8,426:varui4fromui8,427:vari8fromui8,428:varui8fromi8," +
            "429:varui8fromui1,430:varui8fromi2,431:varui8fromr4,432:varui8fromr8,433:varui8fromcy," +
            "434:varui8fromdate,435:varui8fromstr,436:varui8fromdisp,437:varui8frombool,438:varui8fromi1," +
            "439:varui8fromui2,440:varui8fromui4,441:varui8fromdec,442:registertypelibforuser," +
            "443:unregistertypelibforuser",
    };

    private static readonly Dictionary<string, Dictionary<int, string>> Parsed = new(StringComparer.Ordinal);

    /// <summary>The lower-case name of an ordinal of a known library (file name with extension), or "ord" and the number.</summary>
    public static string Name(string library, int ordinal)
    {
        var key = library.ToLowerInvariant();
        if (key == "wsock32.dll") key = "ws2_32.dll";
        if (!Tables.TryGetValue(key, out var table)) return $"ord{ordinal}";
        Dictionary<int, string>? names;
        lock (Parsed)
        {
            if (!Parsed.TryGetValue(key, out names))
                Parsed[key] = names = table.Split(',').Select(e => e.Split(':')).ToDictionary(p => int.Parse(p[0], System.Globalization.CultureInfo.InvariantCulture), p => p[1]);
        }
        return names.TryGetValue(ordinal, out var name) ? name : $"ord{ordinal}";
    }
}
