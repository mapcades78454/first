<?php
use PHPUnit\Framework\TestCase;

class StackTest extends TestCase
{

    public function __constructor(){
	    $this->endPoint = null ;
    }
	
	
    public function hhh() {
	$this->sub = null ; 
	$this->sub = new stdClass();
	print "ij";
    }

    public function testPushAndPop()
    {
        $stack = [];
        $this->assertSame(0, count($stack));

        array_push($stack, 'foo');
        $this->assertSame('foo', $stack[count($stack)-1]);
        $this->assertSame(1, count($stack));

        $this->assertSame('foo', array_pop($stack));
        $this->assertSame(0, count($stack));
    }
    
    public function kkk(){
        reuturn "ok223";
    }
}
