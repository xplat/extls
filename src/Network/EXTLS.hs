{-# LANGUAGE ForeignFunctionInterface #-}

module Network.EXTLS where

import           Data.Bits
import qualified Data.ByteString as B
import           Data.ByteString.Internal (createAndTrim)
import           Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import           Data.Functor
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr

-- a socket as a pair of callbacks
-- use, e.g., Network.Socket.sendBuf and Network.Socket.recvBuf
data Endpoint = Endpoint {
    send :: Ptr Word8 -> Int -> IO Int,
    recv :: Ptr Word8 -> Int -> IO Int
  }

-- abstract types from openssl
newtype BIO = BIO (Ptr BIO)
newtype SSL = SSL (Ptr SSL)
newtype SSL_CTX = SSL_CTX (Ptr SSL_CTX)

data TLS = TLS {
    tlsRawSSL :: Ptr SSL,
    tlsEndpoint :: Endpoint
  }

-- note -- SSL_read will do an incomplete read if you ask for more than is left in the current TLS record
foreign import ccall safe "SSL_read" raw_read :: Ptr SSL -> Ptr a -> CInt -> IO CInt

-- note -- SSL_write will never do a partial write when blocking unless specifically asked to with SSL_set_mode or SSL_CTX_set_mode
foreign import ccall safe "SSL_write" raw_write :: Ptr SSL -> Ptr a -> CInt -> IO CInt

foreign import ccall safe "SSL_set_bio" set_bio :: Ptr SSL -> Ptr BIO -> Ptr BIO -> IO ()

foreign import ccall safe "SSL_set_mode" set_mode :: Ptr SSL -> CLong -> IO CLong

-- note -- may return NULL on error
foreign import ccall safe "SSL_new" raw_new :: Ptr SSL_CTX -> IO (Ptr SSL)

mode_auto_retry :: CLong
mode_auto_retry = 0x4

mode_release_buffers :: CLong
mode_release_buffers = 0x10

-- XXX add error checking for nonpositive length and SSL error returns
wrap_buf :: (Ptr SSL -> Ptr a -> CInt -> IO CInt) -> (TLS -> Ptr a -> Int -> IO Int)
wrap_buf f (TLS { tlsRawSSL = ssl }) buf n =
  fromIntegral <$> f ssl buf (fromIntegral n)

read_buf :: TLS -> Ptr a -> Int -> IO Int
read_buf = wrap_buf raw_read

write_buf :: TLS -> Ptr a -> Int -> IO Int
write_buf = wrap_buf raw_write

read :: TLS -> Int -> IO B.ByteString
read h n = createAndTrim n (flip (read_buf h) n)

write :: TLS -> B.ByteString -> IO Int
write h s = unsafeUseAsCStringLen s (uncurry (write_buf h))
