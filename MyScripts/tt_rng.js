function SeededRandom(){}

function SRnextBytes(ba)
{
    var i;
    for(i = 0; i < ba.length; i++)
    {
        ba[i] = Math.floor(Math.random() * 256);
    }
}

SeededRandom.prototype.nextBytes = SRnextBytes;

undefined;