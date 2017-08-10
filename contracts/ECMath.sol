pragma solidity ^0.4.8;

// Library for secp256r1
library ECMath {


  //curve parameters secp256r1
  uint256 constant a=115792089210356248762697446949407573530086143415290314195533631308867097853948;
  uint256 constant b=41058363725152142129326129780047268409114441015993725554835256314039467401291;
  uint256 constant gx=48439561293906451759052585252797914202762949526041747995844080717082404635286;
  uint256 constant gy=36134250956749795798585127919587881956611106672985015071877198253568414405109;
  uint256 constant p=115792089210356248762697446949407573530086143415290314195533631308867097853951;
  uint256 constant n=115792089210356248762697446949407573529996955224135760342422259061068512044369;
  uint256 constant h=1;

  /*
  //signature parameters
  //04 uncompressed public key, qx,qy exactly 128bit each
  //signature: 30 indicates start, 44 indicates total length of signature
  //02 indicates start of s; 20/21 length
  //02 indicates start of r; 20/21 indicates length
  //e sha256(message)
  uint256 e=0x9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0; //message
  uint256 r=0x6933a06a9b5e654fad879364b58b819feb491810efcb90120423d5e827af4a74; //signature
  uint256 s=0x0f9e643bc2b5124759040955312b6c0227ff21058d3f5bf1266741cc72a3a6ead; //signature
  uint256 qx=0xb7435ff8eab13f5ddfd96a56f7cd23aa7d1d9fc6f5938b3f8f707b1e990be509; //public key x-coordinate signer
  uint256 qy=0xa2e0d3cf29f61d6e49247f48f546b9569c5d7fba10a05bc25b7949db4a74e6d4; //public key y-coordinate signer

  //Toy example
  //curve parameters secp256r1
  uint256 constant a=2;
  uint256 constant b=2;
  uint256 constant gx=5;
  uint256 constant gy=1;
  uint256 constant p=17;
  uint256 constant n=19;
  uint256 constant h=01;

  //signature parameters
  uint256 e=8; //message
  uint256 r=10; //signature
  uint256 s=13; //signature
  uint256 qx=9; //public key x-coordinate signer
  uint256 qy=16; //public key y-coordinate signer


  function testsignature() returns(bool) {
    return ecdsaverify(qx,qy,e,r,s);
  }
  */

  function ecdsaverify(uint256 qx, uint256 qy, uint256 e, uint256 r, uint256 s) returns (bool) {

    if (!isPoint(qx,qy)) {
      return false;
    }

    //temporary variables
    uint256 w;
    uint256 u1;
    uint256 u2;
    uint256[3] memory T1;
    uint256[3] memory T2;
    w=invmod(s,n);
    u1=mulmod(e,w,n);
    u2=mulmod(r,w,n);
    T1=ecmul([gx,gy,1],u1);
    T2=ecmul([qx,qy,1],u2);
    T2=ecadd(T1,T2);
    if (r==JtoA(T2)[0]) {
      return true;
    }
    return false;
  }

  //function checks if point (x1,y1) is on curve, x1 and y1 affine coordinate parameters
  function isPoint(uint256 x1, uint256 y1) private returns (bool) {
    //point fulfills y^2=x^3+ax+b?
    if (mulmod(y1,y1,p) == addmod(mulmod(x1,mulmod(x1,x1,p),p),addmod(mulmod(a,x1,p),b,p),p)) {
      return (true);
    }
    else {
      return (false);
    }
  }

  // point addition for elliptic curve in jacobian coordinates
  // formula from https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
  function ecadd(uint256[3] P, uint256[3] Q) private returns (uint256[3] R) {

    uint256 u1;
    uint256 u2;
    uint256 s1;
    uint256 s2;

    if (Q[0]==0 && Q[1]==0 && Q[2]==0) {
      return P;
    }

    u1 = mulmod(P[0],mulmod(Q[2],Q[2],p),p);
    u2 = mulmod(Q[0],mulmod(P[2],P[2],p),p);
    s1 = mulmod(P[1],mulmod(mulmod(Q[2],Q[2],p),Q[2],p),p);
    s2 = mulmod(Q[1],mulmod(mulmod(P[2],P[2],p),P[2],p),p);

    if (u1==u2) {
      if (s1 != s2) {
        R[0]=1;
        R[1]=1;
        R[2]=0;
        return R;
      }
      else {
        return ecdouble(P);
      }
    }

    uint256 h;
    uint256 r;

    h = addmod(u2,(p-u1),p);
    r = addmod(s2,(p-s1),p);

    R[0] = addmod(addmod(mulmod(r,r,p),(p-mulmod(h,mulmod(h,h,p),p)),p),(p-mulmod(2,mulmod(u1,mulmod(h,h,p),p),p)),p);
    R[1] = addmod(mulmod(r,addmod(mulmod(u1,mulmod(h,h,p),p),(p-R[0]),p),p),(p-mulmod(s1,mulmod(h,mulmod(h,h,p),p),p)),p);
    R[2] = mulmod(h,mulmod(P[2],Q[2],p),p);

    return (R);
  }

  //point doubling for elliptic curve in jacobian coordinates
  //formula from https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
  function ecdouble(uint256[3] P) private returns(uint256[3] R){

    //return point at infinity
    if (P[1]==0) {
      R[0]=1;
      R[1]=1;
      R[2]=0;
      return (R);
    }

    uint256 m;
    uint256 s;

    s = mulmod(4,mulmod(P[0],mulmod(P[1],P[1],p),p),p);
    m = addmod(mulmod(3,mulmod(P[0],P[0],p),p),mulmod(a,mulmod(mulmod(P[2],P[2],p),mulmod(P[2],P[2],p),p),p),p);
    R[0] = addmod(mulmod(m,m,p),(p-mulmod(s,2,p)),p);
    R[1] = addmod(mulmod(m,addmod(s,(p-R[0]),p),p),(p-mulmod(8,mulmod(mulmod(P[1],P[1],p),mulmod(P[1],P[1],p),p),p)),p);
    R[2] = mulmod(2,mulmod(P[1],P[2],p),p);

    return (R);

  }

  // function for elliptic curve multiplication in jacobian coordinates using Double-and-add method
  function ecmul(uint256[3] P, uint256 d) private returns (uint256[3] R) {

    R[0]=0;
    R[1]=0;
    R[2]=0;

    //return (0,0) if d=0 or (x1,y1)=(0,0)
    if (d == 0 || ((P[0]==0) && (P[1]==0)) ) {
      return (R);
    }
    uint256[3] memory T;
    T[0]=P[0]; //x-coordinate temp
    T[1]=P[1]; //y-coordinate temp
    T[2]=P[2]; //z-coordiante temp

    while (d != 0) {
      if ((d & 1) == 1) {  //if last bit is 1 add T to result
        R = ecadd(T,R);
      }
      T = ecdouble(T);    //double temporary coordinates
      d=d/2;              //"cut off" last bit
    }

    return R;
  }

  //jacobian to affine coordinates transfomration
  function JtoA(uint256[3] P) private returns (uint256[2] Pnew) {
    uint zInv = invmod(P[2],p);
    uint zInv2 = mulmod(zInv, zInv, p);
    Pnew[0] = mulmod(P[0], zInv2, p);
    Pnew[1] = mulmod(P[1], mulmod(zInv,zInv2,p), p);
  }

  //computing inverse by using euclidean algorithm
  function invmod(uint256 a, uint p) private returns(uint256 invA) {
    uint256 t=0;
    uint256 newT=1;
    uint256 r=p;
    uint256 newR=a;
    uint256 q;
    while (newR != 0) {
      q = r / newR;

      (t, newT) = (newT, addmod(t , (p - mulmod(q, newT,p)) , p));
      (r, newR) = (newR, r - q * newR );
    }

    return t;
  }

}
