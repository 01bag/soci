import fractions
import math



# include encode and decode
def dele(a,b):
    a=a-b
    return a
class EncodedNumber(object):
    """Represents a float or int encoded for Paillier encryption.

    For end users, this class is mainly useful for specifying precision
    when adding/multiplying an :class:`EncryptedNumber` by a scalar.

    If you want to manually encode a number for Paillier encryption,
    then use :meth:`encode`, if de-serializing then use
    :meth:`__init__`.


    .. note::
        If working with other Paillier libraries you will have to agree on
        a specific :attr:`BASE` and :attr:`LOG2_BASE` - inheriting from this
        class and overriding those two attributes will enable this.

    Notes:
      Paillier encryption is only defined for non-negative integers less
      than :attr:`PaillierPublicKey.n`. Since we frequently want to use
      signed integers and/or floating point numbers (luxury!), values
      should be encoded as a valid integer before encryption.

      The operations of addition and multiplication [1]_ must be
      preserved under this encoding. Namely:

      1. Decode(Encode(a) + Encode(b)) = a + b
      2. Decode(Encode(a) * Encode(b)) = a * b

      for any real numbers a and b.

      Representing signed integers is relatively easy: we exploit the
      modular arithmetic properties of the Paillier scheme. We choose to
      represent only integers between
      +/-:attr:`~PaillierPublicKey.max_int`, where `max_int` is
      approximately :attr:`~PaillierPublicKey.n`/3 (larger integers may
      be treated as floats). The range of values between `max_int` and
      `n` - `max_int` is reserved for detecting overflows. This encoding
      scheme supports properties #1 and #2 above.

      Representing floating point numbers as integers is a harder task.
      Here we use a variant of fixed-precision arithmetic. In fixed
      precision, you encode by multiplying every float by a large number
      (e.g. 1e6) and rounding the resulting product. You decode by
      dividing by that number. However, this encoding scheme does not
      satisfy property #2 above: upon every multiplication, you must
      divide by the large number. In a Paillier scheme, this is not
      possible to do without decrypting. For some tasks, this is
      acceptable or can be worked around, but for other tasks this can't
      be worked around.

      In our scheme, the "large number" is allowed to vary, and we keep
      track of it. It is:

        :attr:`BASE` ** :attr:`exponent`

      One number has many possible encodings; this property can be used
      to mitigate the leak of information due to the fact that
      :attr:`exponent` is never encrypted.

      For more details, see :meth:`encode`.

    .. rubric:: Footnotes

    ..  [1] Technically, since Paillier encryption only supports
      multiplication by a scalar, it may be possible to define a
      secondary encoding scheme `Encode'` such that property #2 is
      relaxed to:

        Decode(Encode(a) * Encode'(b)) = a * b

      We don't do this.


    Args:
      public_key (PaillierPublicKey): public key for which to encode
        (this is necessary because :attr:`~PaillierPublicKey.max_int`
        varies)
      encoding (int): The encoded number to store. Must be positive and
        less than :attr:`~PaillierPublicKey.max_int`.
      exponent (int): Together with :attr:`BASE`, determines the level
        of fixed-precision used in encoding the number.

    Attributes:
      public_key (PaillierPublicKey): public key for which to encode
        (this is necessary because :attr:`~PaillierPublicKey.max_int`
        varies)
      encoding (int): The encoded number to store. Must be positive and
        less than :attr:`~PaillierPublicKey.max_int`.
      exponent (int): Together with :attr:`BASE`, determines the level
        of fixed-precision used in encoding the number.
    """
    BASE = 10
    """Base to use when exponentiating. Larger `BASE` means
    that :attr:`exponent` leaks less information. If you vary this,
    you'll have to manually inform anyone decoding your numbers.
    """
    DEFAULT_EXPONENT = 22

    def __init__(self, encoding, exponent):
        self.encoding = encoding
        self.exponent = exponent


    @classmethod
    def encode(cls, scalar, precision=None, max_exponent=None):
        """Return an encoding of an int or float.

        This encoding is carefully chosen so that it supports the same
        operations as the Paillier cryptosystem.

        If *scalar* is a float, first approximate it as an int, `int_rep`:

            scalar = int_rep * (:attr:`BASE` ** :attr:`exponent`),

        for some (typically negative) integer exponent, which can be
        tuned using *precision* and *max_exponent*. Specifically,
        :attr:`exponent` is chosen to be equal to or less than
        *max_exponent*, and such that the number *precision* is not
        rounded to zero.

        Having found an integer representation for the float (or having
        been given an int `scalar`), we then represent this integer as
        a non-negative integer < :attr:`~PaillierPublicKey.n`.

        Paillier homomorphic arithemetic works modulo
        :attr:`~PaillierPublicKey.n`. We take the convention that a
        number x < n/3 is positive, and that a number x > 2n/3 is
        negative. The range n/3 < x < 2n/3 allows for overflow
        detection.

        Args:
          public_key (PaillierPublicKey): public key for which to encode
            (this is necessary because :attr:`~PaillierPublicKey.n`
            varies).
          scalar: an int or float to be encrypted.
            If int, it must satisfy abs(*value*) <
            :attr:`~PaillierPublicKey.n`/3.
            If float, it must satisfy abs(*value* / *precision*) <<
            :attr:`~PaillierPublicKey.n`/3
            (i.e. if a float is near the limit then detectable
            overflow may still occur)
          precision (float): Choose exponent (i.e. fix the precision) so
            that this number is distinguishable from zero. If `scalar`
            is a float, then this is set so that minimal precision is
            lost. Lower precision leads to smaller encodings, which
            might yield faster computation.
          max_exponent (int): Ensure that the exponent of the returned
            `EncryptedNumber` is at most this.

        Returns:
          EncodedNumber: Encoded form of *scalar*, ready for encryption
          against *public_key*.
        """
        # Calculate the maximum exponent for desired precision
        if precision is None:
            if isinstance(scalar, int) or isinstance(scalar, float):
                if max_exponent is None:
                    exponent = cls.DEFAULT_EXPONENT
                else:
                    exponent = max_exponent
            else:
                raise TypeError("Don't know the precision of type %s."
                            % type(scalar))
        else:
            exponent = - math.floor(math.log(precision, cls.BASE))

        int_rep = round(fractions.Fraction(scalar) * cls.BASE ** exponent)

        # Wrap negative numbers by adding n
        return cls(int_rep, exponent)

    def decode(self):
        return self.encoding / (self.BASE ** self.exponent)
        #return round(self.encoding / (self.BASE ** self.exponent), self.exponent)
