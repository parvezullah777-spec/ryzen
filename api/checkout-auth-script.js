/* ── CUSTOMER ACCOUNTS + PERSISTENCE ── */
var CUSTOMER_TOKEN_KEY='ryzen_customer_token';
var GUEST_CART_KEY='ryzen_guest_cart';
var GUEST_WL_KEY='ryzen_guest_wl';

function getCustomerToken(){return localStorage.getItem(CUSTOMER_TOKEN_KEY);}
function setCustomerToken(t){localStorage.setItem(CUSTOMER_TOKEN_KEY,t);}

function saveCartToStorage(){
  if(getCustomerToken())return; // logged-in customers are backed by the DB, not localStorage
  localStorage.setItem(GUEST_CART_KEY,JSON.stringify(cart));
}
function saveWLToStorage(){
  if(getCustomerToken())return;
  localStorage.setItem(GUEST_WL_KEY,JSON.stringify(wl));
}
function loadCartFromStorage(){
  try{
    var raw=localStorage.getItem(GUEST_CART_KEY);
    cart=raw?JSON.parse(raw):[];
    cart.forEach(function(i){if(!i.k)i.k=i.name+'|'+i.size;});
  }catch(e){cart=[];}
}
function loadWLFromStorage(){
  try{
    var raw=localStorage.getItem(GUEST_WL_KEY);
    wl=raw?JSON.parse(raw):[];
  }catch(e){wl=[];}
}
loadCartFromStorage();
loadWLFromStorage();

/* ── CHECKOUT AUTH MODAL ── */
function openCheckoutAuth(){
  if(!cart.length){toast('Add items to cart first!');return;}
  caShow('choice');
  document.getElementById('checkout-auth').style.display='flex';
  document.body.style.overflow='hidden';
}
function closeCheckoutAuth(){
  document.getElementById('checkout-auth').style.display='none';
  document.body.style.overflow='';
}
function caShow(which){
  ['choice','signin','signup'].forEach(function(id){
    document.getElementById('ca-'+id).style.display=(id===which)?'block':'none';
  });
}
function continueAsGuest(){
  closeCheckoutAuth();
  openAddr();
}

function caSubmitSignin(ev){
  ev.preventDefault();
  var email=document.getElementById('ca-signin-email').value.trim();
  var password=document.getElementById('ca-signin-password').value;
  var errEl=document.getElementById('ca-signin-error');
  errEl.textContent='';
  fetch('/api/customers?action=login',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({email:email,password:password})
  }).then(function(r){return r.json().then(function(d){return {ok:r.ok,data:d};});})
  .then(function(res){
    if(!res.ok){errEl.textContent=res.data.error||'Sign in failed';return;}
    onCustomerAuthed(res.data);
  }).catch(function(){errEl.textContent='Network error, please try again.';});
  return false;
}

function caSubmitSignup(ev){
  ev.preventDefault();
  var name=document.getElementById('ca-signup-name').value.trim();
  var email=document.getElementById('ca-signup-email').value.trim();
  var phone=document.getElementById('ca-signup-phone').value.trim();
  var password=document.getElementById('ca-signup-password').value;
  var errEl=document.getElementById('ca-signup-error');
  errEl.textContent='';
  fetch('/api/customers?action=signup',{
    method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:name,email:email,phone:phone,password:password})
  }).then(function(r){return r.json().then(function(d){return {ok:r.ok,data:d};});})
  .then(function(res){
    if(!res.ok){errEl.textContent=res.data.error||'Sign up failed';return;}
    onCustomerAuthed(res.data);
  }).catch(function(){errEl.textContent='Network error, please try again.';});
  return false;
}

/* Called after a successful sign-in or sign-up. Merges whatever's in the
   guest cart/wishlist into the account, then replaces local state with
   the server's merged version, prefills the address form if one is on
   file, and proceeds straight to checkout. */
function onCustomerAuthed(data){
  setCustomerToken(data.token);
  var guestCart=cart.slice(), guestWL=wl.slice();

  fetch('/api/customers?action=merge',{
    method:'POST',
    headers:{'Content-Type':'application/json',Authorization:'Bearer '+data.token},
    body:JSON.stringify({cart:guestCart,wishlist:guestWL})
  }).then(function(r){return r.json();})
  .then(function(merged){
    cart=(merged.cart||[]).map(function(i){return {k:i.name+'|'+i.size,name:i.name,price:+i.price,size:i.size,qty:i.qty};});
    wl=(merged.wishlist||[]).map(function(i){return {name:i.name,price:+i.price};});
    localStorage.removeItem(GUEST_CART_KEY);
    localStorage.removeItem(GUEST_WL_KEY);
    updateCart();
    updateWL();

    if(merged.address){
      shipInfo=null; // force re-verification of pincode even with prefilled data
      document.getElementById('addr-name').value=merged.address.name||'';
      document.getElementById('addr-phone').value=merged.address.phone||'';
      document.getElementById('addr-email').value=merged.address.email||'';
      if(merged.address.state){
        document.getElementById('addr-state').value=merged.address.state;
        onStateChange();
        setTimeout(function(){
          document.getElementById('addr-city').value=merged.address.city||'';
        },0);
      }
      document.getElementById('addr-pincode').value=merged.address.pincode||'';
      document.getElementById('addr-line1').value=merged.address.line1||'';
      document.getElementById('addr-line2').value=merged.address.line2||'';
    }

    closeCheckoutAuth();
    toast('Signed in! Your saved items were added to your cart.');
    openAddr();
  }).catch(function(){
    closeCheckoutAuth();
    openAddr(); // even if merge fails, don't block checkout
  });
}
