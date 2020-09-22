//window.supercop = supercop_wasm ? supercop_wasm: null;
window.supercop = null;
window.scrypt = null;
window.SCRYPT_PARAMS = {
    N: Math.pow(2, 17),
    R: 8,
    P: 1,
    OutputLength: 32
};

function showNotify(level, title, message) {
  $.notify({
    title: title,
    message: message,
  },{
    element: 'body',
    type: level,
    placement: {
      from: "bottom",
      align: "left"
    },
    offset: {
      x: 0,
      y: 80
    }
  });
}

function showErrorNotifyWithTitle(title, message) {
  showNotify('danger', title, message);
}

function showWarningNotifyWithTitle(title, message) {
  showNotify('warning', title, message);
}

function showInfoNotifyWithTitle(title, message) {
  showNotify('info', title, message);
}


function showErrorNotify(message) {
  showNotify('danger', null, message);
}

function showWarningNotify(message) {
  showNotify('warning', null, message);
}

function showInfoNotify(message) {
  showNotify('info', null, message);
}

function showError(error) {
  showErrorNotify(error.msg);
}

var theOpendToken = [];
function itemOnMouseOver(item) {
  $(item).find('a:first').css({display: 'inline'})

}
function itemOnMouseOut(item) {
  $(item).find('a:first').css({display: 'none'})
}


function shareToString(share) {
  if (!share.encoding) {
    return share.value;
  }

  if (share.encoding.toLowerCase() == 'utf-8') {
    /*
    var bytes = base32.decode.asBytes(share.value);
    if (!bytes || bytes.length == 0)
      return share.value;
    var words = byteArrayToWordArray(bytes);
    return CryptoJS.enc.Utf8.stringify(words);
    */
    return share.value;
  }
  return share.value;
}


function doRestoreFromToken() {
  if (restClient.getSalt() == defaultTokenTypePrefix) {
    showErrorNotify("Entropy Salt could not be empty.");
    $('#open-button').removeAttr('disabled');
    return;
  };
  if (!restClient.getPassphrase() || restClient.getPassphrase().length < 6) {
    showErrorNotify("Passphrase could not be empty.");
    $('#open-button').removeAttr('disabled');
    return;
  }

  $('#open-indicator').css({display: 'inline-block'});
  restClient.getShares(function(result) {
    $('#open-button').removeAttr('disabled');
    console.log(result);
    $('#open-indicator').css({display: 'none'});
    if(result.code != 0) {
      if (result.code == -1) {
        showErrorNotify("Krypton Token does not exist.")
        return;
      }
      showError(result);
      return;
    }
    // gotoGuideScreen();
    restClient.restoreVaults(result.data, function(result) {
      if(result.code != 0) {
        if (result.code == -1) {
          showErrorNotify("Krypton Token does not exist.")
          return;
        }
        showError(result);
        return;
      }

      showInfoNotify("Restore succeed. Auto back to workspace 5 seconds later");
      setTimeout(function() {
        window.location.href='index.html'
      }, 5000);
    });
  });
}

function doBackupAsToken() {

  if (restClient.getSalt() == defaultTokenTypePrefix) {
    showErrorNotify("Entropy Salt could not be empty.");
    $('#open-button').removeAttr('disabled');
    return;
  };
  if (!restClient.getPassphrase() || restClient.getPassphrase().length < 6) {
    showErrorNotify("Passphrase too weak.");
    $('#open-button').removeAttr('disabled');
    return;
  }

  $('#open-indicator').css({display: 'inline-block'});
  restClient.saveShare(g_vaults, function(result) {
    console.log(result);
    $('#open-button').removeAttr('disabled');
    $('#open-indicator').css({display: 'none'});
    if(result.code != 0) {
      showError(result);
      return;
    }
    showInfoNotify("Backup succeed.");
  });
}


var backupOrRestoreWithTokenFn = function() {};
function scryptOnReady(scrypt) {
    window.scrypt = scrypt;
    backupOrRestoreWithTokenFn();
}

function supercopOnReady() {
  $('#page-load-indicator').css({display: 'none'});
}
var g_vaults = [];
function initialUI(cb) {
  let search = window.location.search;
  let action = 'backup';
  if (search != null && search.length > 0) {
    let urlParams = new URLSearchParams(search);
    action = urlParams.get('action') || 'backup';
  }

  if (action == 'backup') {
    gotoBackup();
    restClient.listVaults(function(result) {
      if (result.code == 0) {
        g_vaults = result.data;
      }
      cb();
    });
  } else { 
    gotoRestore();
    cb();
  }
}

function documentOnReady() {
  initialUI(function() {
    initial_supercop_wapper(function() {
      window.supercop = supercop_wasm ? supercop_wasm: null;
      supercop.ready(supercopOnReady);
    })
  })
}

$(document).ready(documentOnReady);


function restoreClicked() {
    $('#open-button').attr('disabled', 'disabled');
    if (window.scrypt) {
      doRestoreFromToken()
    } else {
      backupOrRestoreWithTokenFn = doRestoreFromToken;
      scrypt_module_factory(scryptOnReady, {requested_total_memory: 33554432 * 10});
    }
}

function backupClicked() {
  $('#open-button').attr('disabled', 'disabled');
  if (window.scrypt) {
    doBackupAsToken()
  } else {
    backupOrRestoreWithTokenFn = doBackupAsToken;
    scrypt_module_factory(scryptOnReady, {requested_total_memory: 33554432 * 10});
  }
}

