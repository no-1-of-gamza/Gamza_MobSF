function hook(){
	Java.perform(function(){
		var handler = Java.use("android.os.Handler");
		var sendMessage = handler.sendEmptyMessage.overload("int");
		sendMessage.implementation = function(param){
			var retval = sendMessage.call(this, param);

			bypassLocale();
			bypassRootDetection1();
			bypassRootDetection2();
			bypassEmulatorDetection();

			return retval;
		}
	});
}

function bypassLocale(){
	Java.perform(function(){
		Java.use("java.util.Locale").getLanguage.overload().implementation = function(){
			return "ko";
		}
	});
}

function bypassRootDetection1(){
	Java.perform(function() {
		var contains = Java.use("java.lang.String").contains.overload("java.lang.CharSequence");
		contains.implementation = function(compareStr){
			if(compareStr == "test-keys"){
				return false;
			}
			return contains.call(this, compareStr);
		}
	});
}

function bypassRootDetection2(){
	Java.perform(function(){
		var fileClass = Java.use("java.io.File").$init.overload("java.lang.String");
		fileClass.implementation = function(pathname){
			if(pathname == "/system/app/Superuser.apk"){
				return fileClass.call(this, "/nothing");
			}
			return fileClass.call(this, pathname);
		}
	});
}

function bypassEmulatorDetection(){
	Java.perform(function(){
		var indexof = Java.use("java.lang.String").indexOf.overload("java.lang.String");
		indexof.implementation = function(compareStr){
			if(compareStr == "goldfish"){
				return Java.use("int").$new(-1);
			}
			return indexof.call(this, compareStr);
		}
	});
}

hook();